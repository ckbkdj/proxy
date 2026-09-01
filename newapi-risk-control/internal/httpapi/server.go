package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/audit"
	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/events"
	"github.com/ckbkdj/newapi-risk-control/internal/gateway"
	"github.com/ckbkdj/newapi-risk-control/internal/pipeline"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
)

//go:embed web/*
var webAssets embed.FS

type claimsKey struct{}
type Server struct {
	cfg config.Config
	store *store.Store
	redis *cache.Redis
	kafka *events.Kafka
	cipher *security.Cipher
	audit *audit.Engine
	gateway *gateway.Gateway
	traces *pipeline.Pipeline
	log *slog.Logger
	nonceMu sync.Mutex
	nonces map[string]time.Time
}

func New(cfg config.Config, st *store.Store, rc *cache.Redis, k *events.Kafka, cipher *security.Cipher, ae *audit.Engine, gw *gateway.Gateway, traces *pipeline.Pipeline, log *slog.Logger) *Server {
	return &Server{cfg:cfg,store:st,redis:rc,kafka:k,cipher:cipher,audit:ae,gateway:gw,traces:traces,log:log,nonces:map[string]time.Time{}}
}

func (s *Server) Handler() http.Handler {
	mux:=http.NewServeMux()
	mux.HandleFunc("/healthz",s.health)
	mux.HandleFunc("/readyz",s.ready)
	mux.HandleFunc("/metrics",s.metrics)
	mux.Handle("/gateway/",s.gateway)
	mux.HandleFunc("/api/v1/traces/ingest",s.ingestTraces)
	mux.HandleFunc("/admin/api/v1/login",s.login)
	mux.Handle("/admin/api/v1/",s.withAdminAuth(http.HandlerFunc(s.adminDispatch)))
	assets,_:=fs.Sub(webAssets,"web")
	mux.Handle("/admin/",http.StripPrefix("/admin/",http.FileServer(http.FS(assets))))
	mux.HandleFunc("/admin",func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,"/admin/",http.StatusTemporaryRedirect)})
	return s.securityHeaders(s.accessLog(mux))
}

func (s *Server) health(w http.ResponseWriter,r *http.Request){jsonResponse(w,http.StatusOK,map[string]interface{}{"ok":true,"service":"riskgate","time":time.Now().UTC()})}
func (s *Server) ready(w http.ResponseWriter,r *http.Request){
	ctx,cancel:=context.WithTimeout(r.Context(),2*time.Second);defer cancel()
	if err:=s.store.Ping(ctx);err!=nil{jsonError(w,http.StatusServiceUnavailable,"postgres_unavailable");return}
	if s.cfg.RedisRequired{if err:=s.redis.Ping(ctx);err!=nil{jsonError(w,http.StatusServiceUnavailable,"redis_unavailable");return}}
	jsonResponse(w,http.StatusOK,map[string]interface{}{"ok":true,"postgres":true,"redis":s.redis.Enabled(),"kafka":s.kafka.Enabled()})
}
func (s *Server) metrics(w http.ResponseWriter,r *http.Request){
	ctx,cancel:=context.WithTimeout(r.Context(),2*time.Second);defer cancel();stats,err:=s.store.Stats(ctx);if err!=nil{http.Error(w,"metrics unavailable",http.StatusServiceUnavailable);return}
	w.Header().Set("Content-Type","text/plain; version=0.0.4")
	_,_=fmt.Fprintf(w,"riskgate_routes_enabled %d\nriskgate_rules_enabled %d\nriskgate_traces_last_hour %d\nriskgate_blocks_last_hour %d\nriskgate_outbox_pending %d\nriskgate_outbox_dead %d\nriskgate_default_partition_rows %d\n",
		stats.RoutesEnabled,stats.RulesEnabled,stats.TracesLastHour,stats.BlockedLastHour,stats.OutboxPending,stats.OutboxDead,stats.DefaultPartition)
}

func (s *Server) login(w http.ResponseWriter,r *http.Request){
	if r.Method!=http.MethodPost{methodNotAllowed(w);return}
	if ok,_:=s.redis.Allow(r.Context(),"login:"+s.clientIP(r),0.2,10);s.redis.Enabled()&&!ok{jsonError(w,http.StatusTooManyRequests,"too_many_login_attempts");return}
	var in struct{Username string `json:"username"`;Password string `json:"password"`}
	if !decodeJSON(w,r,64<<10,&in){return}
	user,err:=s.store.FindAdmin(r.Context(),strings.TrimSpace(in.Username));if err!=nil||!user.Enabled||!security.VerifyPassword(user.PasswordHash,in.Password){time.Sleep(150*time.Millisecond);jsonError(w,http.StatusUnauthorized,"invalid_credentials");return}
	token,err:=security.IssueJWT(s.cfg.AdminJWTSecret,user.ID,user.Username,user.Role,8*time.Hour);if err!=nil{jsonError(w,http.StatusInternalServerError,"token_issue_failed");return}
	jsonResponse(w,http.StatusOK,map[string]interface{}{"token":token,"expires_in":int((8*time.Hour).Seconds()),"user":map[string]string{"id":user.ID,"username":user.Username,"role":user.Role}})
}

func (s *Server) withAdminAuth(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	auth:=strings.TrimSpace(r.Header.Get("Authorization"));if !strings.HasPrefix(strings.ToLower(auth),"bearer "){jsonError(w,http.StatusUnauthorized,"missing_bearer_token");return}
	claims,err:=security.ParseJWT(s.cfg.AdminJWTSecret,strings.TrimSpace(auth[7:]));if err!=nil{jsonError(w,http.StatusUnauthorized,"invalid_token");return}
	next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),claimsKey{},claims)))
})}
func claimsFrom(ctx context.Context)*security.Claims{c,_:=ctx.Value(claimsKey{}).(*security.Claims);return c}
func requireRole(w http.ResponseWriter,r *http.Request,roles ...string)bool{c:=claimsFrom(r.Context());if c==nil{jsonError(w,http.StatusUnauthorized,"invalid_token");return false};for _,role:=range roles{if c.Role==role{return true}};jsonError(w,http.StatusForbidden,"insufficient_role");return false}

func (s *Server) ingestTraces(w http.ResponseWriter,r *http.Request){
	if r.Method!=http.MethodPost{methodNotAllowed(w);return}
	body,err:=io.ReadAll(io.LimitReader(r.Body,2<<20));if err!=nil||len(body)>=2<<20{jsonError(w,http.StatusRequestEntityTooLarge,"payload_too_large");return}
	timestamp,err:=strconv.ParseInt(r.Header.Get("X-Risk-Timestamp"),10,64);if err!=nil{jsonError(w,http.StatusUnauthorized,"invalid_timestamp");return}
	nonce:=r.Header.Get("X-Risk-Nonce");signature:=r.Header.Get("X-Risk-Signature");keyID:=r.Header.Get("X-Risk-Key-ID");if keyID==""{keyID="newapi"}
	if err:=security.VerifyTraceSignature(s.cfg.TraceHMACSecret,timestamp,nonce,signature,body,time.Now(),5*time.Minute);err!=nil{jsonError(w,http.StatusUnauthorized,"invalid_signature");return}
	if !s.claimNonce(r.Context(),keyID,nonce){jsonError(w,http.StatusConflict,"replayed_nonce");return}
	var wrapper struct{Events []core.TraceIngest `json:"events"`};var eventsIn []core.TraceIngest
	if json.Unmarshal(body,&wrapper)==nil&&len(wrapper.Events)>0{eventsIn=wrapper.Events}else{var one core.TraceIngest;if json.Unmarshal(body,&one)!=nil{jsonError(w,http.StatusBadRequest,"invalid_json");return};eventsIn=[]core.TraceIngest{one}}
	if len(eventsIn)>1000{jsonError(w,http.StatusBadRequest,"too_many_events");return}
	now:=time.Now().UTC();accepted:=0
	for _,event:=range eventsIn{
		created:=now;if event.OccurredAt!=nil&&!event.OccurredAt.Before(now.AddDate(0,0,-30))&&!event.OccurredAt.After(now.Add(5*time.Minute)){created=event.OccurredAt.UTC()}
		method:=event.Method;if method==""{method="POST"}
		trace:=core.Trace{ID:security.NewUUID(),ExternalRequestID:bounded(event.ExternalRequestID,256),ParentRequestID:bounded(event.ParentRequestID,256),
			RouteSlug:bounded(event.RouteSlug,64),TenantID:bounded(event.TenantID,128),UserIDHash:security.HashOpaque(s.cfg.PromptHashSecret,event.UserID),
			APIKeyHash:security.HashOpaque(s.cfg.PromptHashSecret,event.APIKeyFingerprint),Model:bounded(event.Model,256),Provider:bounded(event.Provider,64),
			Method:bounded(method,16),Path:bounded(event.Path,1024),HTTPStatus:event.HTTPStatus,Outcome:bounded(event.Outcome,64),
			Metadata:security.SanitizeMetadata(event.Metadata,64<<10),CreatedAt:created,ClientIPHash:security.HashOpaque(s.cfg.PromptHashSecret,s.clientIP(r))}
		s.traces.Emit(trace);accepted++
	}
	jsonResponse(w,http.StatusAccepted,map[string]interface{}{"accepted":accepted})
}

func (s *Server) claimNonce(ctx context.Context,keyID,nonce string)bool{
	if nonce==""||len(nonce)>256{return false}
	if s.redis.Enabled(){ok,err:=s.redis.ClaimNonce(ctx,keyID,nonce,10*time.Minute);if err==nil{return ok}}
	now:=time.Now();key:=keyID+":"+nonce;s.nonceMu.Lock();defer s.nonceMu.Unlock();for k,expiry:=range s.nonces{if expiry.Before(now){delete(s.nonces,k)}};if _,exists:=s.nonces[key];exists{return false};s.nonces[key]=now.Add(10*time.Minute);return true
}

func (s *Server) securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("Referrer-Policy","no-referrer");w.Header().Set("Permissions-Policy","camera=(), microphone=(), geolocation=()");w.Header().Set("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:");next.ServeHTTP(w,r)})}
func (s *Server) accessLog(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){start:=time.Now();rw:=&statusWriter{ResponseWriter:w,status:200};next.ServeHTTP(rw,r);if r.URL.Path!="/healthz"{s.log.Info("http request","method",r.Method,"path",r.URL.Path,"status",rw.status,"duration_ms",time.Since(start).Milliseconds())}})}
type statusWriter struct{http.ResponseWriter;status int}
func(w *statusWriter)WriteHeader(status int){w.status=status;w.ResponseWriter.WriteHeader(status)}
func(w *statusWriter)Flush(){if f,ok:=w.ResponseWriter.(http.Flusher);ok{f.Flush()}}

func (s *Server) clientIP(r *http.Request)string{if s.cfg.TrustProxyHeaders{if raw:=r.Header.Get("X-Forwarded-For");raw!=""{return strings.TrimSpace(strings.Split(raw,",")[0])};if raw:=r.Header.Get("X-Real-IP");raw!=""{return raw}};host,_,err:=net.SplitHostPort(r.RemoteAddr);if err==nil{return host};return r.RemoteAddr}
func (s *Server) auditAdmin(r *http.Request,action,resourceType,resourceID string,before,after interface{}){c:=claimsFrom(r.Context());if c==nil{return};requestID:=bounded(r.Header.Get("X-Request-ID"),256);ipHash:=security.HashOpaque(s.cfg.PromptHashSecret,s.clientIP(r));if err:=s.store.WriteAdminAudit(r.Context(),c.Subject,c.Username,c.Role,action,resourceType,resourceID,requestID,ipHash,before,after);err!=nil{s.log.Warn("admin audit write failed","error",err)}}

func decodeJSON(w http.ResponseWriter,r *http.Request,max int64,out interface{})bool{defer r.Body.Close();dec:=json.NewDecoder(io.LimitReader(r.Body,max));dec.DisallowUnknownFields();if err:=dec.Decode(out);err!=nil{jsonError(w,http.StatusBadRequest,"invalid_json");return false};if dec.Decode(&struct{}{})!=io.EOF{jsonError(w,http.StatusBadRequest,"multiple_json_values");return false};return true}
func jsonResponse(w http.ResponseWriter,status int,value interface{}){w.Header().Set("Content-Type","application/json; charset=utf-8");w.Header().Set("Cache-Control","no-store");w.WriteHeader(status);_ = json.NewEncoder(w).Encode(value)}
func jsonError(w http.ResponseWriter,status int,code string){jsonResponse(w,status,map[string]interface{}{"error":map[string]interface{}{"code":code,"message":code}})}
func methodNotAllowed(w http.ResponseWriter){w.Header().Set("Allow","GET, POST, PUT, DELETE");jsonError(w,http.StatusMethodNotAllowed,"method_not_allowed")}
func bounded(v string,max int)string{v=strings.TrimSpace(v);if len(v)>max{return v[:max]};return v}
func parseTime(raw string)(time.Time,error){if raw==""{return time.Time{},nil};return time.Parse(time.RFC3339,raw)}
func isNotFound(err error)bool{return errors.Is(err,context.Canceled)}
