package events

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

type Kafka struct{writer *kafka.Writer;transport *kafka.Transport;brokers []string;topic string;enabled bool}
func NewKafka(cfg config.Config)(*Kafka,error){if !cfg.KafkaEnabled(){return &Kafka{},nil};transport:=&kafka.Transport{ClientID:cfg.KafkaClientID,DialTimeout:5*time.Second,IdleTimeout:60*time.Second};if cfg.KafkaTLS{transport.TLS=&tls.Config{MinVersion:tls.VersionTLS12}};mechanism,err:=saslMechanism(cfg);if err!=nil{return nil,err};transport.SASL=mechanism;writer:=&kafka.Writer{Addr:kafka.TCP(cfg.KafkaBrokers...),Topic:cfg.KafkaTopic,Balancer:&kafka.Hash{},RequiredAcks:kafka.RequireAll,Async:false,BatchSize:200,BatchBytes:1<<20,BatchTimeout:25*time.Millisecond,WriteTimeout:10*time.Second,ReadTimeout:10*time.Second,Transport:transport};return &Kafka{writer:writer,transport:transport,brokers:cfg.KafkaBrokers,topic:cfg.KafkaTopic,enabled:true},nil}
func saslMechanism(cfg config.Config)(sasl.Mechanism,error){switch strings.ToLower(cfg.KafkaSASLMechanism){case "":return nil,nil;case "plain":return plain.Mechanism{Username:cfg.KafkaSASLUsername,Password:cfg.KafkaSASLPassword},nil;case "scram-sha-256":return scram.Mechanism(scram.SHA256,cfg.KafkaSASLUsername,cfg.KafkaSASLPassword);case "scram-sha-512":return scram.Mechanism(scram.SHA512,cfg.KafkaSASLUsername,cfg.KafkaSASLPassword);default:return nil,fmt.Errorf("unsupported Kafka SASL mechanism %q",cfg.KafkaSASLMechanism)}}
func(k *Kafka)Enabled()bool{return k!=nil&&k.enabled&&k.writer!=nil};func(k *Kafka)Topic()string{if k==nil{return ""};return k.topic}
func(k *Kafka)Close()error{if k==nil{return nil};var err error;if k.writer!=nil{err=k.writer.Close()};if k.transport!=nil{k.transport.CloseIdleConnections()};return err}
func(k *Kafka)Publish(ctx context.Context,key string,value []byte,headers map[string]string)error{if !k.Enabled(){return errors.New("kafka disabled")};h:=make([]kafka.Header,0,len(headers));for name,value:=range headers{h=append(h,kafka.Header{Key:name,Value:[]byte(value)})};return k.writer.WriteMessages(ctx,kafka.Message{Key:[]byte(key),Value:value,Headers:h,Time:time.Now().UTC()})}
func(k *Kafka)ConfigureRetention(ctx context.Context,hours int)error{if !k.Enabled(){return errors.New("kafka disabled")};if hours<1||hours>87600{return errors.New("Kafka retention must be between 1 and 87600 hours")};client:=&kafka.Client{Addr:kafka.TCP(k.brokers...),Timeout:10*time.Second,Transport:k.transport};resp,err:=client.IncrementalAlterConfigs(ctx,&kafka.IncrementalAlterConfigsRequest{Resources:[]kafka.IncrementalAlterConfigsRequestResource{{ResourceType:kafka.ResourceTypeTopic,ResourceName:k.topic,Configs:[]kafka.IncrementalAlterConfigsRequestConfig{{Name:"retention.ms",Value:strconv.FormatInt(int64(hours)*int64(time.Hour/time.Millisecond),10),ConfigOperation:kafka.ConfigOperationSet}}}}});if err!=nil{return fmt.Errorf("configure Kafka topic retention: %w",err)};for _,resource:=range resp.Resources{if resource.Error!=nil{return fmt.Errorf("configure Kafka resource %s: %w",resource.ResourceName,resource.Error)}};return nil}
