package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/redis/go-redis/v9"
)

type Redis struct{client *redis.Client;prefix string;enabled bool}
type DLQMessage struct{ID string;Trace core.Trace}
var tokenBucketScript=redis.NewScript(`local key=KEYS[1] local now=tonumber(ARGV[1]) local rate=tonumber(ARGV[2]) local burst=tonumber(ARGV[3]) local ttl=tonumber(ARGV[4]) local values=redis.call('HMGET',key,'tokens','updated') local tokens=tonumber(values[1]) local updated=tonumber(values[2]) if tokens==nil then tokens=burst end if updated==nil then updated=now end local elapsed=math.max(0,now-updated) tokens=math.min(burst,tokens+elapsed*rate) local allowed=0 if tokens>=1 then tokens=tokens-1 allowed=1 end redis.call('HSET',key,'tokens',tokens,'updated',now) redis.call('PEXPIRE',key,ttl) return {allowed,tokens}`)
var acquireSemaphoreScript=redis.NewScript(`local key=KEYS[1] local now=tonumber(ARGV[1]) local expires=tonumber(ARGV[2]) local limit=tonumber(ARGV[3]) local token=ARGV[4] redis.call('ZREMRANGEBYSCORE',key,'-inf',now) local count=redis.call('ZCARD',key) if count>=limit then return 0 end redis.call('ZADD',key,expires,token) redis.call('PEXPIRE',key,math.max(1000,expires-now+1000)) return 1`)
func New(ctx context.Context,cfg config.Config)(*Redis,error){if cfg.RedisURL==""{return &Redis{prefix:cfg.RedisPrefix},nil};opts,err:=redis.ParseURL(cfg.RedisURL);if err!=nil{return nil,fmt.Errorf("parse REDIS_URL: %w",err)};client:=redis.NewClient(opts);pingCtx,cancel:=context.WithTimeout(ctx,3*time.Second);defer cancel();if err:=client.Ping(pingCtx).Err();err!=nil{_=client.Close();if cfg.RedisRequired{return nil,fmt.Errorf("Redis is required but unavailable: %w",err)};return &Redis{prefix:cfg.RedisPrefix},nil};return &Redis{client:client,prefix:cfg.RedisPrefix,enabled:true},nil}
func(r *Redis)Close()error{if r.client==nil{return nil};return r.client.Close()};func(r *Redis)Enabled()bool{return r!=nil&&r.enabled&&r.client!=nil};func(r *Redis)Ping(ctx context.Context)error{if !r.Enabled(){return errors.New("redis disabled")};return r.client.Ping(ctx).Err()}
func(r *Redis)key(parts ...string)string{out:=r.prefix;for _,p:=range parts{out+=":"+p};return out}
func(r *Redis)Allow(ctx context.Context,scope string,rate float64,burst int)(bool,error){if !r.Enabled(){return false,errors.New("redis disabled")};if rate<=0||burst<=0{return false,errors.New("invalid rate limit")};now:=float64(time.Now().UnixNano())/float64(time.Second);ttl:=int64((float64(burst)/rate)*2000)+10000;res,err:=tokenBucketScript.Run(ctx,r.client,[]string{r.key("limit",scope)},now,rate,burst,ttl).Slice();if err!=nil{return false,err};allowed,err:=strconv.ParseInt(fmt.Sprint(res[0]),10,64);return allowed==1,err}
func(r *Redis)Acquire(ctx context.Context,scope,token string,limit int,ttl time.Duration)(bool,error){if !r.Enabled(){return false,errors.New("redis disabled")};now:=time.Now().UnixMilli();res,err:=acquireSemaphoreScript.Run(ctx,r.client,[]string{r.key("semaphore",scope)},now,now+ttl.Milliseconds(),limit,token).Int();return res==1,err}
func(r *Redis)Release(ctx context.Context,scope,token string)error{if !r.Enabled(){return nil};return r.client.ZRem(ctx,r.key("semaphore",scope),token).Err()}
func(r *Redis)ClaimNonce(ctx context.Context,keyID,nonce string,ttl time.Duration)(bool,error){if !r.Enabled(){return false,errors.New("redis disabled")};return r.client.SetNX(ctx,r.key("nonce",keyID,nonce),"1",ttl).Result()}
func(r *Redis)GetDecision(ctx context.Context,hash string)(core.Decision,bool){if !r.Enabled(){return core.Decision{},false};b,err:=r.client.Get(ctx,r.key("audit",hash)).Bytes();if err!=nil{return core.Decision{},false};var d core.Decision;if json.Unmarshal(b,&d)!=nil{return core.Decision{},false};return d,true}
func(r *Redis)PutDecision(ctx context.Context,hash string,d core.Decision,ttl time.Duration){if !r.Enabled()||ttl<=0{return};b,_:=json.Marshal(d);_=r.client.Set(ctx,r.key("audit",hash),b,ttl).Err()}
func(r *Redis)DeleteRoute(ctx context.Context,slug string){if r.Enabled(){_=r.client.Del(ctx,r.key("route",slug)).Err()}}
func(r *Redis)PushTraceDLQ(ctx context.Context,trace core.Trace,ttl time.Duration)error{if !r.Enabled(){return errors.New("redis disabled")};b,err:=json.Marshal(trace);if err!=nil{return err};key:=r.key("dlq","traces");if err:=r.client.XAdd(ctx,&redis.XAddArgs{Stream:key,MaxLen:200000,Approx:true,Values:map[string]interface{}{"trace":b}}).Err();err!=nil{return err};if ttl>0{_=r.client.Expire(ctx,key,ttl).Err()};return nil}
func(r *Redis)EnsureTraceDLQGroup(ctx context.Context,group string)error{if !r.Enabled(){return errors.New("redis disabled")};err:=r.client.XGroupCreateMkStream(ctx,r.key("dlq","traces"),group,"0").Err();if err!=nil&&!strings.Contains(err.Error(),"BUSYGROUP"){return err};return nil}
func(r *Redis)ReadTraceDLQ(ctx context.Context,group,consumer string,count int64,block time.Duration)([]DLQMessage,error){if !r.Enabled(){return nil,errors.New("redis disabled")};streams,err:=r.client.XReadGroup(ctx,&redis.XReadGroupArgs{Group:group,Consumer:consumer,Streams:[]string{r.key("dlq","traces"),">"},Count:count,Block:block}).Result();if err==redis.Nil{return nil,nil};if err!=nil{return nil,err};var out []DLQMessage;for _,stream:=range streams{for _,msg:=range stream.Messages{raw:=fmt.Sprint(msg.Values["trace"]);var t core.Trace;if json.Unmarshal([]byte(raw),&t)==nil{out=append(out,DLQMessage{ID:msg.ID,Trace:t})}}};return out,nil}
func(r *Redis)AckTraceDLQ(ctx context.Context,group string,ids ...string)error{if !r.Enabled()||len(ids)==0{return nil};return r.client.XAck(ctx,r.key("dlq","traces"),group,ids...).Err()}
