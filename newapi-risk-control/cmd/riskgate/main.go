package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/audit"
	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/events"
	"github.com/ckbkdj/newapi-risk-control/internal/gateway"
	"github.com/ckbkdj/newapi-risk-control/internal/httpapi"
	"github.com/ckbkdj/newapi-risk-control/internal/pipeline"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
)

func main(){
	if len(os.Args)>1&&os.Args[1]=="healthcheck"{healthcheck();return}
	cfg,err:=config.Load();if err!=nil{fatal("configuration error",err)}
	level:=slog.LevelInfo;if strings.EqualFold(cfg.LogLevel,"debug"){level=slog.LevelDebug}else if strings.EqualFold(cfg.LogLevel,"warn"){level=slog.LevelWarn}else if strings.EqualFold(cfg.LogLevel,"error"){level=slog.LevelError}
	log:=slog.New(slog.NewJSONHandler(os.Stdout,&slog.HandlerOptions{Level:level}));slog.SetDefault(log)
	ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer stop()

	cipher,err:=security.NewCipher(cfg.MasterEncryptionKey);if err!=nil{fatal("initialize encryption",err)}
	st,err:=store.New(ctx,cfg);if err!=nil{fatal("initialize PostgreSQL",err)};defer st.Close()
	migrationPath:=os.Getenv("MIGRATIONS_PATH");if migrationPath==""{migrationPath="migrations/001_init.sql"}
	if err:=st.Migrate(ctx,migrationPath);err!=nil{fatal("database migration",err)}
	if err:=st.EnsureTracePartitions(ctx,time.Now(),cfg.DefaultRetentionDays);err!=nil{fatal("initialize trace partitions",err)}
	passwordHash,err:=security.HashPassword(cfg.BootstrapAdminPassword);if err!=nil{fatal("bootstrap admin password",err)}
	if err:=st.BootstrapAdmin(ctx,cfg.BootstrapAdminUsername,passwordHash,cfg.BootstrapAdminRole);err!=nil{fatal("bootstrap admin",err)}
	if err:=st.SeedBuiltinRules(ctx,audit.BuiltinRules());err!=nil{fatal("seed cyber rules",err)}
	if err:=seedDefaultAuditProfile(ctx,st,cipher);err!=nil{fatal("seed default audit profile",err)}

	rc,err:=cache.New(ctx,cfg);if err!=nil{fatal("initialize Redis",err)};defer rc.Close()
	kafkaClient,err:=events.NewKafka(cfg);if err!=nil{fatal("initialize Kafka",err)};defer kafkaClient.Close()
	tracePipeline:=pipeline.New(cfg,st,rc,kafkaClient,log);tracePipeline.Start(ctx)
	auditEngine:=audit.New(cfg,st,rc,cipher);auditEngine.Start(ctx)
	gw:=gateway.New(cfg,st,rc,cipher,auditEngine,tracePipeline,log)
	api:=httpapi.New(cfg,st,rc,kafkaClient,cipher,auditEngine,gw,tracePipeline,log)

	httpServer:=&http.Server{Addr:cfg.ListenAddr,Handler:api.Handler(),ReadHeaderTimeout:10*time.Second,ReadTimeout:30*time.Second,
		IdleTimeout:120*time.Second,MaxHeaderBytes:1<<20}
	errCh:=make(chan error,1);go func(){log.Info("riskgate started","listen",cfg.ListenAddr,"env",cfg.AppEnv);errCh<-httpServer.ListenAndServe()}()
	select{case <-ctx.Done():log.Info("shutdown signal received");case err:=<-errCh:if !errors.Is(err,http.ErrServerClosed){fatal("HTTP server",err)}}
	shutdownCtx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel();if err:=httpServer.Shutdown(shutdownCtx);err!=nil{log.Error("graceful shutdown failed","error",err)}
}

func seedDefaultAuditProfile(ctx context.Context,st *store.Store,cipher *security.Cipher)error{
	endpoint:=strings.TrimSpace(os.Getenv("AUDIT_MODEL_ENDPOINT"));model:=strings.TrimSpace(os.Getenv("AUDIT_MODEL_NAME"));if endpoint==""||model==""{return nil}
	profiles,err:=st.ListAuditProfiles(ctx);if err!=nil{return err};for _,p:=range profiles{if p.Name=="default-small-model"{return nil}}
	keyCipher,err:=cipher.EncryptString(os.Getenv("AUDIT_MODEL_API_KEY"));if err!=nil{return err}
	threshold:=.72;if raw:=os.Getenv("AUDIT_MODEL_BLOCK_THRESHOLD");raw!=""{if v,e:=strconv.ParseFloat(raw,64);e==nil&&v>=0&&v<=1{threshold=v}}
	failMode:=strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_MODEL_FAIL_MODE")));if failMode==""{failMode="closed"}
	_,err=st.UpsertAuditProfile(ctx,core.AuditProfile{Name:"default-small-model",Endpoint:endpoint,Model:model,APIKeyCipher:keyCipher,Enabled:true,FailMode:failMode,
		BlockThreshold:threshold,TimeoutMS:8000,MaxInputChars:32000,CacheTTLSeconds:600})
	return err
}

func healthcheck(){
	url:="http://127.0.0.1:8080/healthz";if len(os.Args)>2{url=os.Args[2]};client:=http.Client{Timeout:2*time.Second};resp,err:=client.Get(url);if err!=nil||resp.StatusCode!=http.StatusOK{if err==nil{_ = resp.Body.Close()};os.Exit(1)};_ = resp.Body.Close()
}
func fatal(message string,err error){_,_=fmt.Fprintf(os.Stderr,"%s: %v\n",message,err);os.Exit(1)}
