package pipeline

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/events"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
)

type Pipeline struct {
	cfg     config.Config
	store   *store.Store
	redis   *cache.Redis
	kafka   *events.Kafka
	log     *slog.Logger
	queue   chan core.Trace
	policy  atomic.Value // core.StoragePolicy
	started sync.Once
}

func New(cfg config.Config, st *store.Store, rc *cache.Redis, k *events.Kafka, log *slog.Logger) *Pipeline {
	p:=&Pipeline{cfg:cfg,store:st,redis:rc,kafka:k,log:log,queue:make(chan core.Trace,cfg.TraceQueueSize)}
	p.policy.Store(core.StoragePolicy{RetentionDays:cfg.DefaultRetentionDays,PostgresEnabled:true,RedisBufferEnabled:true,RedisBufferTTLHours:72,
		KafkaEnabled:cfg.KafkaEnabled(),KafkaRetentionHours:cfg.KafkaRetentionHours})
	return p
}

func (p *Pipeline) Start(ctx context.Context){p.started.Do(func(){
	p.refreshPolicy(ctx)
	for i:=0;i<p.cfg.TraceWorkers;i++{go p.traceWorker(ctx,i)}
	for i:=0;i<p.cfg.OutboxWorkers;i++{go p.outboxWorker(ctx,i)}
	go p.policyWorker(ctx)
	go p.retentionWorker(ctx)
	if p.redis.Enabled(){_ = p.redis.EnsureTraceDLQGroup(ctx,"riskgate-trace-replay");go p.dlqWorker(ctx)}
})}

func (p *Pipeline) Emit(trace core.Trace){
	if trace.ID==""{trace.ID=security.NewUUID()};if trace.CreatedAt.IsZero(){trace.CreatedAt=time.Now().UTC()}
	timer:=time.NewTimer(10*time.Millisecond);defer timer.Stop()
	select{case p.queue<-trace:return;case <-timer.C:
		policy:=p.currentPolicy();if policy.RedisBufferEnabled&&p.redis.Enabled(){ctx,cancel:=context.WithTimeout(context.Background(),100*time.Millisecond);defer cancel();
			if err:=p.redis.PushTraceDLQ(ctx,trace,time.Duration(policy.RedisBufferTTLHours)*time.Hour);err==nil{return}}
		p.log.Error("trace queue saturated; event dropped after durable fallback failed","request_id",trace.ID)
	}
}

func (p *Pipeline) traceWorker(ctx context.Context,worker int){
	batch:=make([]core.Trace,0,500);ticker:=time.NewTicker(100*time.Millisecond);defer ticker.Stop()
	flush:=func(){if len(batch)==0{return};copyBatch:=append([]core.Trace(nil),batch...);batch=batch[:0];p.persist(ctx,copyBatch)}
	for{select{case <-ctx.Done():flush();return;case t:=<-p.queue:batch=append(batch,t);if len(batch)>=500{flush()};case <-ticker.C:flush()}}
}

func (p *Pipeline) persist(ctx context.Context,traces []core.Trace){
	policy:=p.currentPolicy()
	if policy.PostgresEnabled{
		if err:=p.store.InsertTraceBatch(ctx,traces,policy.KafkaEnabled&&p.kafka.Enabled(),p.kafka.Topic());err==nil{return}else{p.log.Error("trace batch database write failed","error",err,"count",len(traces))}
	}else if policy.KafkaEnabled&&p.kafka.Enabled(){
		allOK:=true;for _,t:=range traces{raw,_:=json.Marshal(t);if err:=p.kafka.Publish(ctx,t.ID,raw,map[string]string{"schema":"riskgate.trace.v1"});err!=nil{allOK=false;break}}
		if allOK{return}
	}
	if policy.RedisBufferEnabled&&p.redis.Enabled(){
		ttl:=time.Duration(policy.RedisBufferTTLHours)*time.Hour
		for _,t:=range traces{writeCtx,cancel:=context.WithTimeout(context.Background(),500*time.Millisecond);err:=p.redis.PushTraceDLQ(writeCtx,t,ttl);cancel();if err!=nil{p.log.Error("trace Redis DLQ write failed","error",err,"request_id",t.ID)}}
	}
}

func (p *Pipeline) dlqWorker(ctx context.Context){
	consumer:="consumer-"+security.NewUUID()
	for{select{case <-ctx.Done():return;default:}
		items,err:=p.redis.ReadTraceDLQ(ctx,"riskgate-trace-replay",consumer,100,2*time.Second);if err!=nil{p.log.Warn("trace DLQ read failed","error",err);sleep(ctx,time.Second);continue}
		for _,item:=range items{
			policy:=p.currentPolicy();ok:=false
			if policy.PostgresEnabled{ok=p.store.InsertTraceBatch(ctx,[]core.Trace{item.Trace},policy.KafkaEnabled&&p.kafka.Enabled(),p.kafka.Topic())==nil
			}else if policy.KafkaEnabled&&p.kafka.Enabled(){raw,_:=json.Marshal(item.Trace);ok=p.kafka.Publish(ctx,item.Trace.ID,raw,map[string]string{"schema":"riskgate.trace.v1"})==nil}
			if ok{_ = p.redis.AckTraceDLQ(ctx,"riskgate-trace-replay",item.ID)}else{sleep(ctx,250*time.Millisecond)}
		}
	}
}

func (p *Pipeline) outboxWorker(ctx context.Context,worker int){
	owner:="outbox-"+security.NewUUID()
	for{select{case <-ctx.Done():return;default:}
		policy:=p.currentPolicy();if !policy.KafkaEnabled||!p.kafka.Enabled(){sleep(ctx,time.Second);continue}
		eventsBatch,err:=p.store.LeaseOutbox(ctx,owner,200,30*time.Second);if err!=nil{p.log.Warn("outbox lease failed","error",err);sleep(ctx,time.Second);continue}
		if len(eventsBatch)==0{sleep(ctx,250*time.Millisecond);continue}
		for _,event:=range eventsBatch{
			publishCtx,cancel:=context.WithTimeout(ctx,12*time.Second);err:=p.kafka.Publish(publishCtx,event.Key,event.Payload,event.Headers);cancel()
			if err==nil{_ = p.store.MarkOutboxPublished(ctx,event.ID,owner)}else{_ = p.store.MarkOutboxFailed(ctx,event.ID,owner,err.Error(),event.Attempts)}
		}
	}
}

func (p *Pipeline) policyWorker(ctx context.Context){
	ticker:=time.NewTicker(10*time.Second);defer ticker.Stop();lastRetention:=0
	for{select{case <-ctx.Done():return;case <-ticker.C:
		p.refreshPolicy(ctx);policy:=p.currentPolicy()
		if p.cfg.KafkaAutoConfigureTopic&&policy.KafkaEnabled&&p.kafka.Enabled()&&policy.KafkaRetentionHours!=lastRetention{
			configureCtx,cancel:=context.WithTimeout(ctx,15*time.Second);err:=p.kafka.ConfigureRetention(configureCtx,policy.KafkaRetentionHours);cancel()
			if err!=nil{p.log.Warn("Kafka retention configuration failed","error",err)}else{lastRetention=policy.KafkaRetentionHours}
		}
	}}
}
func (p *Pipeline) refreshPolicy(ctx context.Context){policy,err:=p.store.GetStoragePolicy(ctx);if err!=nil{p.log.Warn("storage policy refresh failed","error",err);return};p.policy.Store(policy)}
func (p *Pipeline) currentPolicy()core.StoragePolicy{return p.policy.Load().(core.StoragePolicy)}

func (p *Pipeline) retentionWorker(ctx context.Context){
	run:=func(){policy:=p.currentPolicy();jobCtx,cancel:=context.WithTimeout(ctx,2*time.Minute);defer cancel();
		if err:=p.store.EnsureTracePartitions(jobCtx,time.Now(),policy.RetentionDays);err!=nil{p.log.Error("ensure trace partitions failed","error",err);return}
		if err:=p.store.PurgeExpiredTraces(jobCtx,policy.RetentionDays,time.Now());err!=nil{p.log.Error("trace retention cleanup failed","error",err)}}
	run();ticker:=time.NewTicker(time.Hour);defer ticker.Stop();for{select{case<-ctx.Done():return;case<-ticker.C:run()}}
}

func sleep(ctx context.Context,d time.Duration){timer:=time.NewTimer(d);defer timer.Stop();select{case<-ctx.Done():case<-timer.C:}}
