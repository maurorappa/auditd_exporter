package main
 
import (
        "encoding/json"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "strconv"
        "time"
 
        "github.com/maurorappa/libaudit-go"
        "github.com/prometheus/client_golang/prometheus"
        "github.com/prometheus/client_golang/prometheus/promhttp"
)
 
 
var (
        msgCh chan libaudit.AuditMessage = make(chan libaudit.AuditMessage)
        RuleStat = prometheus.NewGaugeVec(prometheus.GaugeOpts{
                Name: "RuleStat",
                Help: "event details",
                },
                []string{"rulestats"},
        )
)
 
func init() {
        prometheus.MustRegister(RuleStat)
}
 
func auditProc(e *libaudit.AuditEvent, err error) {
        if err != nil {
                // See if the error is libaudit.ErrorAuditParse, if so convert and also display
                // the audit record we could not parse
                if nerr, ok := err.(libaudit.ErrorAuditParse); ok {
                        fmt.Printf("parser error: %v: %v\n", nerr, nerr.Raw)
                } else {
                        fmt.Printf("callback received error: %v\n", err)
                }
                return
        }
        // Marshal the event to JSON and print
        buf, err := json.Marshal(e)
        if err != nil {
                fmt.Printf("callback was unable to marshal event: %v\n", err)
                return
        }
        fmt.Printf("%v\n", string(buf))
}
 
func main() {
        s, err := libaudit.NewNetlinkConnection()
        if err != nil {
                fmt.Fprintf(os.Stderr, "NetNetlinkConnection: %v\n", err)
                os.Exit(1)
        }
 
        if len(os.Args) != 2 {
                fmt.Printf("usage: %v path_to_rules.json\n", os.Args[0])
                os.Exit(0)
        }
 
        err = libaudit.AuditSetEnabled(s, true)
        if err != nil {
                fmt.Fprintf(os.Stderr, "AuditSetEnabled: %v\n", err)
                os.Exit(1)
        }
 
        err = libaudit.AuditSetPID(s, os.Getpid())
        if err != nil {
                fmt.Fprintf(os.Stderr, "AuditSetPid: %v\n", err)
                os.Exit(1)
        }
        err = libaudit.AuditSetRateLimit(s, 1000)
        if err != nil {
                fmt.Fprintf(os.Stderr, "AuditSetRateLimit: %v\n", err)
                os.Exit(1)
        }
        err = libaudit.AuditSetBacklogLimit(s, 250)
        if err != nil {
                fmt.Fprintf(os.Stderr, "AuditSetBacklogLimit: %v\n", err)
                os.Exit(1)
        }
 
        var ar libaudit.AuditRules
        buf, err := ioutil.ReadFile(os.Args[1])
        if err != nil {
                fmt.Fprintf(os.Stderr, "ReadFile: %v\n", err)
                os.Exit(1)
        }
        // Make sure we can unmarshal the rules JSON to validate it is the correct
        // format
        err = json.Unmarshal(buf, &ar)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Unmarshaling rules JSON: %v\n", err)
                os.Exit(1)
        }
 
        // Remove current rule set and send rules to the kernel
        err = libaudit.DeleteAllRules(s)
        if err != nil {
                fmt.Fprintf(os.Stderr, "DeleteAllRules: %v\n", err)
                os.Exit(1)
        }
        warnings, err := libaudit.SetRules(s, buf)
        if err != nil {
                fmt.Fprintf(os.Stderr, "SetRules: %v\n", err)
                os.Exit(1)
        }
        // Print any warnings we got back but still continue
        for _, x := range warnings {
                fmt.Fprintf(os.Stderr, "ruleset warning: %v\n", x)
        }
 
        doneCh := make(chan bool, 1)
 
        go libaudit.SendAuditMessagesToChannel(s, auditProc, &doneCh, msgCh)
 
        go Mprint(msgCh)
 
        http.Handle("/metrics", promhttp.Handler())
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte(`
         <html>
         <head><title>Audit Exporter</title></head>
         <body>
         <h1>Audit Exporter</h1>
         <p><a href='/metrics'><b>Metrics</b></a></p>
         </body>
         </html>
         `))
        })
        log.Fatal(http.ListenAndServe(":9099", nil))
 
 
}
 
func Mprint(msgCh <-chan libaudit.AuditMessage) {
        fmt.Println("Starting interface...")
        for {
                message := <- msgCh
                fmt.Printf("ID: %s, U: %s, C: %s %s\n", message.Id, message.User, message.Command, message.Args)
                eventid,_ := strconv.Atoi(message.Id)
                RuleStat.WithLabelValues(message.User+" "+message.Command+" "+message.Args).Set(float64(eventid))
                time.Sleep(time.Second * 1)
        }
 
}
