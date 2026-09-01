package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/gateway"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/jackc/pgx/v5"
)

func (s *Server) adminDispatch(w http.ResponseWriter,r *http.Request){
	path:=strings.Trim(strings.TrimPrefix(r.URL.Path,"/admin/api/v1/"),"/")
	switch {
	case path=="runtime":s.handleRuntime(w,r)
	case path=="routes":s.handleRoutes(w,r)
	case strings.HasPrefix(path,"routes/"):s.handleRoute(w,r,strings.TrimPrefix(path,"routes/"))
	case path=="audit-profiles":s.handleProfiles(w,r)
	case strings.HasPrefix(path,"audit-profiles/"):s.handleProfile(w,r,strings.TrimPrefix(path,"audit-profiles/"))
	case path=="rules":s.handleRules(w,r)
	case strings.HasPrefix(path,"rules/"):s.handleRule(w,r,strings.TrimPrefix(path,"rules/"))
	case path=="traces":s.handleTraces(w,r)
	case path=="storage-policy":s.handleStoragePolicy(w,r)
	case path=="audit/dry-run":s.handleAuditDryRun(w,r)
	default:http.NotFound(w,r)
	}
}

func (s *Server) handleRuntime(w http.ResponseWriter,r *http.Request){
	if r.Method!=http.MethodGet{methodNotAllowed(w);return};if !requireRole(w,r,"admin","operator","auditor","viewer"){return}
	stats,err:=s.store.Stats(r.Context());if err!=nil{jsonError(w,http.StatusServiceUnavailable,"runtime_stats_unavailable");return}
	policy,_:=s.store.GetStoragePolicy(r.Context())
	redisOK:=false;if s.redis.Enabled(){ctx,cancel:=contextWithTimeout(r,1500*time.Millisecond);redisOK=s.redis.Ping(ctx)==nil;cancel()}
	jsonResponse(w,http.StatusOK,map[string]interface{}{"stats":stats,"storage_policy":policy,"components":map[string]interface{}{
		"postgres":true,"redis_enabled":s.redis.Enabled(),"redis_healthy":redisOK,"kafka_enabled":s.kafka.Enabled(),
	},"limits":map[string]interface{}{"max_request_bytes":s.cfg.MaxRequestBytes,"max_response_bytes":s.cfg.MaxResponseBytes,"max_sse_frame_bytes":s.cfg.MaxSSEFrameBytes}})
}

func (s *Server) handleRoutes(w http.ResponseWriter,r *http.Request){
	switch r.Method{
	case http.MethodGet:
		if !requireRole(w,r,"admin","operator","auditor","viewer"){return};routes,err:=s.store.ListRoutes(r.Context());if err!=nil{jsonError(w,http.StatusInternalServerError,"list_routes_failed");return}
		out:=make([]map[string]interface{},0,len(routes));for _,route:=range routes{out=append(out,routeView(route,s.cfg.PublicBaseURL))};jsonResponse(w,http.StatusOK,map[string]interface{}{"items":out})
	case http.MethodPost:
		if !requireRole(w,r,"admin","operator"){return};var in core.RouteWrite;if !decodeJSON(w,r,1<<20,&in){return};route,token,err:=s.prepareRoute(r,in,nil);if err!=nil{jsonError(w,http.StatusBadRequest,err.Error());return};saved,err:=s.store.UpsertRoute(r.Context(),route);if err!=nil{jsonError(w,http.StatusConflict,"save_route_failed");return};s.gateway.InvalidateRoute(saved.Slug);s.auditAdmin(r,"create","route",saved.ID,nil,saved);view:=routeView(saved,s.cfg.PublicBaseURL);if token!=""{view["client_token"]=token;view["client_token_note"]="shown_once"};jsonResponse(w,http.StatusCreated,view)
	default:methodNotAllowed(w)
	}
}
func (s *Server) handleRoute(w http.ResponseWriter,r *http.Request,id string){
	id=bounded(id,64);if id==""{http.NotFound(w,r);return};before,err:=s.store.GetRouteByID(r.Context(),id);if err!=nil{if errors.Is(err,pgx.ErrNoRows){http.NotFound(w,r)}else{jsonError(w,http.StatusInternalServerError,"route_lookup_failed")};return}
	switch r.Method{
	case http.MethodPut:
		if !requireRole(w,r,"admin","operator"){return};var in core.RouteWrite;if !decodeJSON(w,r,1<<20,&in){return};in.ID=id;route,token,err:=s.prepareRoute(r,in,&before);if err!=nil{jsonError(w,http.StatusBadRequest,err.Error());return};saved,err:=s.store.UpsertRoute(r.Context(),route);if err!=nil{jsonError(w,http.StatusConflict,"save_route_failed");return};s.gateway.InvalidateRoute(before.Slug);s.gateway.InvalidateRoute(saved.Slug);s.auditAdmin(r,"update","route",id,before,saved);view:=routeView(saved,s.cfg.PublicBaseURL);if token!=""{view["client_token"]=token;view["client_token_note"]="shown_once"};jsonResponse(w,http.StatusOK,view)
	case http.MethodDelete:
		if !requireRole(w,r,"admin"){return};if err:=s.store.DeleteRoute(r.Context(),id);err!=nil{jsonError(w,http.StatusConflict,"delete_route_failed");return};s.gateway.InvalidateRoute(before.Slug);s.auditAdmin(r,"delete","route",id,before,nil);w.WriteHeader(http.StatusNoContent)
	default:methodNotAllowed(w)
	}
}

func (s *Server) prepareRoute(r *http.Request,in core.RouteWrite,current *core.Route)(core.Route,string,error){
	in.Slug=strings.ToLower(strings.TrimSpace(in.Slug));if ok,_:=regexp.MatchString(`^[a-z0-9][a-z0-9_-]{1,62}$`,in.Slug);!ok{return core.Route{},"invalid_route_slug",errors.New("invalid route slug")}
	if strings.TrimSpace(in.Name)==""{return core.Route{},"",errors.New("route_name_required")}
	kind:=strings.ToLower(strings.TrimSpace(in.UpstreamKind));switch kind{case "openai","anthropic","gemini","custom":default:return core.Route{},"",errors.New("unsupported_upstream_kind")}
	allowPrivate:=s.cfg.AllowPrivateUpstreams&&in.AllowPrivateUpstream
	if err:=gateway.ValidateUpstreamURL(r.Context(),in.UpstreamBaseURL,allowPrivate);err!=nil{return core.Route{},"",errors.New("invalid_or_unsafe_upstream_url")}
	parsed,_:=url.Parse(in.UpstreamBaseURL);if s.cfg.Production()&&!allowPrivate&&parsed.Scheme!="https"{return core.Route{},"",errors.New("production_upstream_requires_https")}
	if in.RateLimitRPS<=0{in.RateLimitRPS=100};if in.RateLimitBurst<=0{in.RateLimitBurst=200};if in.MaxInflight<=0{in.MaxInflight=1000};if in.RequestTimeoutMS<=0{in.RequestTimeoutMS=300000}
	if in.RateLimitRPS>1000000||in.RateLimitBurst>10000000||in.MaxInflight>1000000||in.RequestTimeoutMS>3600000{return core.Route{},"",errors.New("route_limit_out_of_range")}
	policy,err:=normalizeErrorPolicy(in.UpstreamErrorPolicy);if err!=nil{return core.Route{},"",err}
	route:=core.Route{ID:in.ID,Slug:in.Slug,Name:bounded(in.Name,256),UpstreamBaseURL:strings.TrimRight(strings.TrimSpace(in.UpstreamBaseURL),"/"),UpstreamKind:kind,
		AuditProfileID:in.AuditProfileID,Enabled:in.Enabled,RateLimitRPS:in.RateLimitRPS,RateLimitBurst:in.RateLimitBurst,MaxInflight:in.MaxInflight,
		RequestTimeoutMS:in.RequestTimeoutMS,AllowPrivateUpstream:in.AllowPrivateUpstream,UpstreamErrorPolicy:policy}
	var shownToken string
	if current!=nil{route.UpstreamAPIKeyCipher=current.UpstreamAPIKeyCipher;route.ClientTokenHash=current.ClientTokenHash;route.ExtraHeadersEncrypted=current.ExtraHeadersEncrypted}
	if in.UpstreamAPIKey!=""{route.UpstreamAPIKeyCipher,err=s.cipher.EncryptString(in.UpstreamAPIKey);if err!=nil{return core.Route{},"",errors.New("encrypt_upstream_key_failed")}}
	if current==nil&&route.UpstreamAPIKeyCipher==""{return core.Route{},"",errors.New("upstream_api_key_required")}
	if in.ClientToken!=""{shownToken=in.ClientToken}else if current==nil{shownToken,err=security.RandomToken(32);if err!=nil{return core.Route{},"",err}}
	if shownToken!=""{route.ClientTokenHash=security.HashOpaque(s.cfg.PromptHashSecret,shownToken)}
	if current==nil&&route.ClientTokenHash==""{return core.Route{},"",errors.New("client_token_required")}
	if in.ExtraHeaders!=nil{raw,_:=json.Marshal(in.ExtraHeaders);route.ExtraHeadersEncrypted,err=s.cipher.EncryptString(string(raw));if err!=nil{return core.Route{},"",errors.New("encrypt_headers_failed")}}
	return route,shownToken,nil
}
func routeView(route core.Route,base string)map[string]interface{}{raw,_:=json.Marshal(route);var out map[string]interface{};_ = json.Unmarshal(raw,&out);out["newapi_base_url"]=strings.TrimRight(base,"/")+"/gateway/"+route.Slug;out["has_upstream_api_key"]=route.UpstreamAPIKeyCipher!="";out["has_client_token"]=route.ClientTokenHash!="";out["has_extra_headers"]=route.ExtraHeadersEncrypted!="";return out}
func normalizeErrorPolicy(raw json.RawMessage)(json.RawMessage,error){
	if len(raw)==0||string(raw)=="null"{b,_:=json.Marshal(core.DefaultUpstreamErrorPolicy());return b,nil}
	var p core.UpstreamErrorPolicy;if err:=json.Unmarshal(raw,&p);err!=nil{return nil,errors.New("invalid_upstream_error_policy")}
	if len(p.NormalizeStatuses)>100||len(p.NormalizeCodes)>100||len(p.MessagePatterns)>50||len(p.PassStatuses)>100{return nil,errors.New("upstream_error_policy_too_large")}
	for _,pattern:=range p.MessagePatterns{if len(pattern)>1024{return nil,errors.New("error_pattern_too_long")};if _,err:=regexp.Compile(pattern);err!=nil{return nil,errors.New("invalid_error_pattern")}}
	return json.Marshal(p)
}

func (s *Server) handleProfiles(w http.ResponseWriter,r *http.Request){
	switch r.Method{
	case http.MethodGet:if !requireRole(w,r,"admin","operator","auditor","viewer"){return};items,err:=s.store.ListAuditProfiles(r.Context());if err!=nil{jsonError(w,http.StatusInternalServerError,"list_profiles_failed");return};jsonResponse(w,http.StatusOK,map[string]interface{}{"items":items})
	case http.MethodPost:if !requireRole(w,r,"admin","operator"){return};var in core.AuditProfileWrite;if !decodeJSON(w,r,1<<20,&in){return};profile,err:=s.prepareProfile(r,in,nil);if err!=nil{jsonError(w,http.StatusBadRequest,err.Error());return};saved,err:=s.store.UpsertAuditProfile(r.Context(),profile);if err!=nil{jsonError(w,http.StatusConflict,"save_profile_failed");return};s.auditAdmin(r,"create","audit_profile",saved.ID,nil,saved);jsonResponse(w,http.StatusCreated,saved)
	default:methodNotAllowed(w)}
}
func (s *Server) handleProfile(w http.ResponseWriter,r *http.Request,id string){
	before,err:=s.store.GetAuditProfile(r.Context(),bounded(id,64));if err!=nil{if errors.Is(err,pgx.ErrNoRows){http.NotFound(w,r)}else{jsonError(w,http.StatusInternalServerError,"profile_lookup_failed")};return}
	switch r.Method{
	case http.MethodPut:if !requireRole(w,r,"admin","operator"){return};var in core.AuditProfileWrite;if !decodeJSON(w,r,1<<20,&in){return};in.ID=before.ID;profile,err:=s.prepareProfile(r,in,&before);if err!=nil{jsonError(w,http.StatusBadRequest,err.Error());return};saved,err:=s.store.UpsertAuditProfile(r.Context(),profile);if err!=nil{jsonError(w,http.StatusConflict,"save_profile_failed");return};s.auditAdmin(r,"update","audit_profile",saved.ID,before,saved);jsonResponse(w,http.StatusOK,saved)
	case http.MethodDelete:if !requireRole(w,r,"admin"){return};if err:=s.store.DeleteAuditProfile(r.Context(),before.ID);err!=nil{jsonError(w,http.StatusConflict,"delete_profile_failed");return};s.auditAdmin(r,"delete","audit_profile",before.ID,before,nil);w.WriteHeader(http.StatusNoContent)
	default:methodNotAllowed(w)}
}
func (s *Server) prepareProfile(r *http.Request,in core.AuditProfileWrite,current *core.AuditProfile)(core.AuditProfile,error){
	if strings.TrimSpace(in.Name)==""||strings.TrimSpace(in.Model)==""{return core.AuditProfile{},errors.New("profile_name_and_model_required")}
	if err:=gateway.ValidateUpstreamURL(r.Context(),in.Endpoint,s.cfg.AllowPrivateUpstreams);err!=nil{return core.AuditProfile{},errors.New("invalid_or_unsafe_audit_endpoint")}
	if in.FailMode==""{in.FailMode="closed"};if in.FailMode!="closed"&&in.FailMode!="open"&&in.FailMode!="shadow"{return core.AuditProfile{},errors.New("invalid_fail_mode")}
	if in.BlockThreshold<=0{in.BlockThreshold=.72};if in.BlockThreshold>1{return core.AuditProfile{},errors.New("invalid_block_threshold")};if in.TimeoutMS<=0{in.TimeoutMS=8000};if in.TimeoutMS>120000{return core.AuditProfile{},errors.New("invalid_timeout")}
	if in.MaxInputChars<=0{in.MaxInputChars=32000};if in.MaxInputChars>262144{return core.AuditProfile{},errors.New("max_input_too_large")};if in.CacheTTLSeconds<0||in.CacheTTLSeconds>86400{return core.AuditProfile{},errors.New("invalid_cache_ttl")};if len(in.SystemPrompt)>32768{return core.AuditProfile{},errors.New("system_prompt_too_large")}
	p:=core.AuditProfile{ID:in.ID,Name:bounded(in.Name,256),Endpoint:strings.TrimRight(strings.TrimSpace(in.Endpoint),"/"),Model:bounded(in.Model,256),Enabled:in.Enabled,FailMode:in.FailMode,BlockThreshold:in.BlockThreshold,TimeoutMS:in.TimeoutMS,MaxInputChars:in.MaxInputChars,CacheTTLSeconds:in.CacheTTLSeconds,SystemPrompt:in.SystemPrompt}
	var err error;if current!=nil{p.APIKeyCipher=current.APIKeyCipher};if in.APIKey!=""{p.APIKeyCipher,err=s.cipher.EncryptString(in.APIKey);if err!=nil{return core.AuditProfile{},errors.New("encrypt_audit_key_failed")}}
	return p,nil
}

func (s *Server) handleRules(w http.ResponseWriter,r *http.Request){
	switch r.Method{
	case http.MethodGet:if !requireRole(w,r,"admin","operator","auditor","viewer"){return};items,err:=s.store.ListRules(r.Context(),false);if err!=nil{jsonError(w,http.StatusInternalServerError,"list_rules_failed");return};jsonResponse(w,http.StatusOK,map[string]interface{}{"items":items})
	case http.MethodPost:if !requireRole(w,r,"admin","operator"){return};var rule core.RiskRule;if !decodeJSON(w,r,256<<10,&rule){return};if err:=validateRule(&rule);err!=nil{jsonError(w,http.StatusBadRequest,err.Error());return};rule.ID="";rule.Builtin=false;saved,err:=s.store.UpsertRule(r.Context(),rule);if err!=nil{jsonError(w,http.StatusConflict,"save_rule_failed");return};_ = s.audit.Refresh(r.Context());s.auditAdmin(r,"create","risk_rule",saved.ID,nil,saved);jsonResponse(w,http.StatusCreated,saved)
	default:methodNotAllowed(w)}
}
func (s *Server) handleRule(w http.ResponseWriter,r *http.Request,id string){
	before,err:=s.store.GetRule(r.Context(),bounded(id,64));if err!=nil{if errors.Is(err,pgx.ErrNoRows){http.NotFound(w,r)}else{jsonError(w,http.StatusInternalServerError,"rule_lookup_failed")};return}
	switch r.Method{
	case http.MethodPut:if !requireRole(w,r,"admin","operator"){return};var rule core.RiskRule;if !decodeJSON(w,r,256<<10,&rule){return};if err:=validateRule(&rule);err!=nil{jsonError(w,http.StatusBadRequest,err.Error());return};rule.ID=before.ID;rule.Builtin=before.Builtin;saved,err:=s.store.UpsertRule(r.Context(),rule);if err!=nil{jsonError(w,http.StatusConflict,"save_rule_failed");return};_ = s.audit.Refresh(r.Context());s.auditAdmin(r,"update","risk_rule",saved.ID,before,saved);jsonResponse(w,http.StatusOK,saved)
	case http.MethodDelete:if !requireRole(w,r,"admin"){return};if before.Builtin{jsonError(w,http.StatusConflict,"builtin_rule_cannot_be_deleted");return};if err:=s.store.DeleteRule(r.Context(),before.ID);err!=nil{jsonError(w,http.StatusConflict,"delete_rule_failed");return};_ = s.audit.Refresh(r.Context());s.auditAdmin(r,"delete","risk_rule",before.ID,before,nil);w.WriteHeader(http.StatusNoContent)
	default:methodNotAllowed(w)}
}
func validateRule(rule *core.RiskRule)error{rule.Name=bounded(rule.Name,256);rule.Category=bounded(rule.Category,128);if rule.Name==""||rule.Category==""||rule.Pattern==""{return errors.New("rule_fields_required")};if len(rule.Pattern)>4096{return errors.New("rule_pattern_too_large")};if _,err:=regexp.Compile(rule.Pattern);err!=nil{return errors.New("invalid_rule_regex")};if rule.Action==""{rule.Action="block"};if rule.Action!="block"&&rule.Action!="review"&&rule.Action!="allow"{return errors.New("invalid_rule_action")};if rule.Score<0||rule.Score>1{return errors.New("invalid_rule_score")};return nil}

func (s *Server) handleTraces(w http.ResponseWriter,r *http.Request){
	if r.Method!=http.MethodGet{methodNotAllowed(w);return};if !requireRole(w,r,"admin","operator","auditor","viewer"){return}
	from,err:=parseTime(r.URL.Query().Get("from"));if err!=nil{jsonError(w,http.StatusBadRequest,"invalid_from_time");return};to,err:=parseTime(r.URL.Query().Get("to"));if err!=nil{jsonError(w,http.StatusBadRequest,"invalid_to_time");return}
	items,err:=s.store.ListTraces(r.Context(),store.TraceFilter{RequestID:bounded(r.URL.Query().Get("request_id"),256),RouteSlug:bounded(r.URL.Query().Get("route"),64),Outcome:bounded(r.URL.Query().Get("outcome"),64),Model:bounded(r.URL.Query().Get("model"),256),From:from,To:to,Limit:store.ParseLimit(r.URL.Query().Get("limit"),100),Offset:store.ParseLimit(r.URL.Query().Get("offset"),0)})
	if err!=nil{jsonError(w,http.StatusInternalServerError,"list_traces_failed");return};jsonResponse(w,http.StatusOK,map[string]interface{}{"items":items})
}

func (s *Server) handleStoragePolicy(w http.ResponseWriter,r *http.Request){
	switch r.Method{
	case http.MethodGet:if !requireRole(w,r,"admin","operator","auditor","viewer"){return};policy,err:=s.store.GetStoragePolicy(r.Context());if err!=nil{jsonError(w,http.StatusInternalServerError,"get_storage_policy_failed");return};jsonResponse(w,http.StatusOK,policy)
	case http.MethodPut:if !requireRole(w,r,"admin"){return};var in core.StoragePolicy;if !decodeJSON(w,r,128<<10,&in){return};if in.StoreRawPrompt{jsonError(w,http.StatusBadRequest,"raw_prompt_storage_forbidden");return};if in.RetentionDays<1||in.RetentionDays>3650||in.RedisBufferTTLHours<1||in.RedisBufferTTLHours>8760||in.KafkaRetentionHours<1||in.KafkaRetentionHours>87600{jsonError(w,http.StatusBadRequest,"storage_policy_out_of_range");return};if in.KafkaEnabled&&!s.kafka.Enabled(){jsonError(w,http.StatusBadRequest,"kafka_not_configured");return};if !in.PostgresEnabled&&!in.RedisBufferEnabled&&!in.KafkaEnabled{jsonError(w,http.StatusBadRequest,"at_least_one_storage_sink_required");return};before,_:=s.store.GetStoragePolicy(r.Context());saved,err:=s.store.SetStoragePolicy(r.Context(),in);if err!=nil{jsonError(w,http.StatusBadRequest,"save_storage_policy_failed");return};s.auditAdmin(r,"update","storage_policy","singleton",before,saved);jsonResponse(w,http.StatusOK,saved)
	default:methodNotAllowed(w)}
}

func (s *Server) handleAuditDryRun(w http.ResponseWriter,r *http.Request){
	if r.Method!=http.MethodPost{methodNotAllowed(w);return};if !requireRole(w,r,"admin","operator","auditor"){return}
	var in struct{ProfileID *string `json:"profile_id"`;Payload json.RawMessage `json:"payload"`;Text string `json:"text"`};if !decodeJSON(w,r,2<<20,&in){return};payload:=in.Payload;if len(payload)==0{payload,_=json.Marshal(map[string]interface{}{"messages":[]map[string]string{{"role":"user","content":in.Text}}})};decision,hash:=s.audit.Audit(r.Context(),in.ProfileID,payload);jsonResponse(w,http.StatusOK,map[string]interface{}{"decision":decision,"prompt_hash":hash})
}

func contextWithTimeout(r *http.Request,d time.Duration)(context.Context,context.CancelFunc){return context.WithTimeout(r.Context(),d)}
var _ = strconv.Itoa
