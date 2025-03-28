
Ùù’¥gosec‘
Efile:///home/flo/Desktop/Git/govwa/vulnerability/idor/idor.go:164-164G401#Use of weak cryptographic primitive 0:b163: func Md5Sum(text string) string {
164: 	hasher := md5.New()
165: 	hasher.Write([]byte(text))
BunknownbÍ			res.Message = "Update Success"
			log.Println("Update Success")

		}
		util.RenderAsJson(w, res)
	}
}

func Md5Sum(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}j∆≤
Afile:///home/flo/Desktop/Git/govwa/vulnerability/csa/csa.go:62-62G401#Use of weak cryptographic primitive 0:_61: func Md5Sum(text string) string {
62: 	hasher := md5.New()
63: 	hasher.Write([]byte(text))
Bunknownbœ			res.Code = 0
		}else{
			res.Code = 1
		}
		util.RenderAsJson(w, res)
	}
}

func Md5Sum(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}j∆
7file:///home/flo/Desktop/Git/govwa/user/user.go:160-160G401#Use of weak cryptographic primitive 0:b159: func Md5Sum(text string) string {
160: 	hasher := md5.New()
161: 	hasher.Write([]byte(text))
Bunknownbî		log.Println(err.Error())
	}
	defer stmt.Close()
	err = stmt.QueryRow(username, pass).Scan(&uData.id, &uData.uname, &uData.cnt)
	return &uData

}

func Md5Sum(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}j∆¶
Cfile:///home/flo/Desktop/Git/govwa/vulnerability/xss/xss.go:100-100G203òThe used method does not auto-escape HTML. This can potentially lead to 'Cross-site Scripting' vulnerabilities, in case the attacker controls the input. 0:p99: 
100: 	data["inlineJS"] = template.HTML(inlineJS) //this will render the javascript on client browser
101: 
Bunknownbª			var name = "%s"
			var city = "%s"
			var number = "%s"
			</script>` //here is the mistake, render value to a javascript that came from client request

	inlineJS := fmt.Sprintf(js,uid, p.Name, p.City, p.PhoneNumber)

	data["title"] = "Cross Site Scripting"

	data["inlineJS"] = template.HTML(inlineJS) //this will render the javascript on client browser

	util.SafeRender(w, r, "template.xss2", data)

}

func HTMLEscapeString(text string)string{
	filter := regexp.MustCompile("<[^>]*>")
	output := filter.ReplaceAllString(text,"")
	return html.EscapeString(output)
}jOÒ
Afile:///home/flo/Desktop/Git/govwa/vulnerability/xss/xss.go:63-63G203òThe used method does not auto-escape HTML. This can potentially lead to 'Cross-site Scripting' vulnerabilities, in case the attacker controls the input. 0:{62: 			data["value"] = template.HTML(value)
63: 			data["term"] = template.HTML(vuln)
64: 			data["details"] = vulnDetails
Bunknownb˝
		if term == ""{
			data["term"] = ""
		}else if vulnDetails == ""{
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(notFound) //vulnerable function
		}else{
			vuln := fmt.Sprintf("<b>%s</b>",term)
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(vuln)
			data["details"] = vulnDetails
		}

	}
	data["title"] = "Cross Site Scripting"
	util.SafeRender(w,r, "template.xss1", data)
}

func xss2Handler(w http.ResponseWriter, r *http.Request, _ httprouter.Params){
jOú
Afile:///home/flo/Desktop/Git/govwa/vulnerability/xss/xss.go:62-62G203òThe used method does not auto-escape HTML. This can potentially lead to 'Cross-site Scripting' vulnerabilities, in case the attacker controls the input. 0:É61: 			vuln := fmt.Sprintf("<b>%s</b>",term)
62: 			data["value"] = template.HTML(value)
63: 			data["term"] = template.HTML(vuln)
Bunknownbü		value := fmt.Sprintf("%s", term)

		if term == ""{
			data["term"] = ""
		}else if vulnDetails == ""{
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(notFound) //vulnerable function
		}else{
			vuln := fmt.Sprintf("<b>%s</b>",term)
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(vuln)
			data["details"] = vulnDetails
		}

	}
	data["title"] = "Cross Site Scripting"
	util.SafeRender(w,r, "template.xss1", data)
}

func xss2Handler(w http.ResponseWriter, r *http.Request, _ httprouter.Params){jOü
Afile:///home/flo/Desktop/Git/govwa/vulnerability/xss/xss.go:59-59G203òThe used method does not auto-escape HTML. This can potentially lead to 'Cross-site Scripting' vulnerabilities, in case the attacker controls the input. 0:}58: 			data["value"] = template.HTML(value)
59: 			data["term"] = template.HTML(notFound) //vulnerable function
60: 		}else{
Bunknownb©		vulnDetails := GetExp(term)

		notFound := fmt.Sprintf("<b><i>%s</i></b> not found",term)
		value := fmt.Sprintf("%s", term)

		if term == ""{
			data["term"] = ""
		}else if vulnDetails == ""{
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(notFound) //vulnerable function
		}else{
			vuln := fmt.Sprintf("<b>%s</b>",term)
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(vuln)
			data["details"] = vulnDetails
		}

	}
	data["title"] = "Cross Site Scripting"
	util.SafeRender(w,r, "template.xss1", data)jOß
Afile:///home/flo/Desktop/Git/govwa/vulnerability/xss/xss.go:58-58G203òThe used method does not auto-escape HTML. This can potentially lead to 'Cross-site Scripting' vulnerabilities, in case the attacker controls the input. 0:í57: 		}else if vulnDetails == ""{
58: 			data["value"] = template.HTML(value)
59: 			data["term"] = template.HTML(notFound) //vulnerable function
Bunknownbõ		term = removeScriptTag(term)
		vulnDetails := GetExp(term)

		notFound := fmt.Sprintf("<b><i>%s</i></b> not found",term)
		value := fmt.Sprintf("%s", term)

		if term == ""{
			data["term"] = ""
		}else if vulnDetails == ""{
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(notFound) //vulnerable function
		}else{
			vuln := fmt.Sprintf("<b>%s</b>",term)
			data["value"] = template.HTML(value)
			data["term"] = template.HTML(vuln)
			data["details"] = vulnDetails
		}

	}
	data["title"] = "Cross Site Scripting"jO¡
9file:///home/flo/Desktop/Git/govwa/util/template.go:45-45G203òThe used method does not auto-escape HTML. This can potentially lead to 'Cross-site Scripting' vulnerabilities, in case the attacker controls the input. 0:Q44: func ToHTML(text string)template.HTML{
45: 	return template.HTML(text)
46: }
Bunknownbˇ}

func UnSafeRender(w http.ResponseWriter, name string, data ...interface{}) {

	template := template.Must(template.ParseGlob("templates/*"))
	template.ExecuteTemplate(w, name, data)
}

func ToHTML(text string)template.HTML{
	return template.HTML(text)
}jO˙
Gfile:///home/flo/Desktop/Git/govwa/vulnerability/sqli/function.go:37-40G201SQL string formatting 0:ï36: 
37: 	getProfileSql := fmt.Sprintf(`SELECT p.user_id, p.full_name, p.city, p.phone_number 
38: 								FROM Profile as p,Users as u 
39: 								where p.user_id = u.id 
40: 								and u.id=%s`, uid) //here is the vulnerable query
41: 	rows, err := DB.Query(getProfileSql)
BunknownbÈfunc NewProfile() *Profile {
	return &Profile{}
}

func (p *Profile) UnsafeQueryGetData(uid string) error {

	/* this funciton use to get data Profile from database with vulnerable query */
	DB, err = database.Connect()

	getProfileSql := fmt.Sprintf(`SELECT p.user_id, p.full_name, p.city, p.phone_number 
								FROM Profile as p,Users as u 
								where p.user_id = u.id 
								and u.id=%s`, uid) //here is the vulnerable query
	rows, err := DB.Query(getProfileSql)
	if err != nil {
		return err //this will return error query to clien hmmmm.
	}
	defer rows.Close()
	//var profile = Profile{}
	for rows.Next() {
		err = rows.Scan(&p.Uid, &p.Name, &p.City, &p.PhoneNumber)
		if err != nil {
			log.Printf("Row scan error: %s", err.Error())jY˘
/file:///home/flo/Desktop/Git/govwa/app.go:71-74G112YPotential Slowloris Attack because ReadHeaderTimeout is not configured in the http.Server 0:v70: 
71: 	s := http.Server{
72: 		Addr:    fmt.Sprintf(":%s", config.Cfg.Webport),
73: 		Handler: router,
74: 	}
75: 
Bunknownb€
	user.SetRouter(router)
	sqlI.SetRouter(router)
	xss.SetRouter(router)
	idor.SetRouter(router)
	csa.SetRouter(router)
	setup.SetRouter(router)
	setting.SetRouter(router)

	s := http.Server{
		Addr:    fmt.Sprintf(":%s", config.Cfg.Webport),
		Handler: router,
	}

	fmt.Printf("Server running at port %s\n", s.Addr)
	fmt.Printf("Open this url %s on your browser to access GoVWA", config.Fullurl)
	fmt.Println("")
	err := s.ListenAndServe()
	if err != nil {
		panic(err)
	}

}jêø
Afile:///home/flo/Desktop/Git/govwa/vulnerability/idor/idor.go:8-8G501;Blocklisted import crypto/md5: weak cryptographic primitive 0:37: 	"net/http"
8: 	"crypto/md5"
9: 	"encoding/hex"
Bunknownbpackage idor

import (

	"log"
	"strconv"
	"net/http"
	"crypto/md5"
	"encoding/hex"

	"github.com/julienschmidt/httprouter"

	"github.com/govwa/user/session"
	"github.com/govwa/util"
	"github.com/govwa/util/middleware"
)

type IDOR struct{}j«Ø
?file:///home/flo/Desktop/Git/govwa/vulnerability/csa/csa.go:7-7G501;Blocklisted import crypto/md5: weak cryptographic primitive 0:36: 	"net/http"
7: 	"crypto/md5"
8: 	"encoding/hex"
Bunknownb‚package csa

import (

	"fmt"
	"net/http"
	"crypto/md5"
	"encoding/hex"

	"github.com/julienschmidt/httprouter"

	"github.com/govwa/util"
	"github.com/govwa/user/session"
	"github.com/govwa/util/middleware"
)

type XSS struct{j«÷
3file:///home/flo/Desktop/Git/govwa/user/user.go:8-8G501;Blocklisted import crypto/md5: weak cryptographic primitive 0:27: 	"strconv"
8: 	"crypto/md5"
9: 	"database/sql"
Bunknownbñpackage user

import (

	"log"
	"net/http"
	"strconv"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"html/template"

	"github.com/govwa/util"
	"github.com/govwa/util/config"
	"github.com/govwa/user/session"
	"github.com/govwa/util/database"
	"github.com/govwa/util/middleware"
j«¡
Efile:///home/flo/Desktop/Git/govwa/vulnerability/idor/idor.go:124-124G104Errors unhandled. 0:3123: 	p := NewProfile()
124: 	p.GetData(sid)
125: 
Bunknownbò		util.RenderAsJson(w, res)
	}
}

func idor2ActionHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	session := session.New()
	sid := session.GetSession(r, "id")
	p := NewProfile()
	p.GetData(sid)

	/* handle request response with json */
	if r.Method == "POST" {
		
		sign := HTMLEscapeString(r.FormValue("signature"))
		uid := HTMLEscapeString(r.FormValue("uid"))
		name := HTMLEscapeString(r.FormValue("name"))
		city := HTMLEscapeString(r.FormValue("city"))
		number := HTMLEscapeString(r.FormValue("number"))
jø∏
Cfile:///home/flo/Desktop/Git/govwa/vulnerability/idor/idor.go:82-82G104Errors unhandled. 0:081: 	p := NewProfile()
82: 	p.GetData(sid)
83: 
Bunknownbî	util.SafeRender(w, r, "template.idor2", data)

}

func idor1ActionHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	session := session.New()
	sid := session.GetSession(r, "id")
	p := NewProfile()
	p.GetData(sid)

	/* handle request response with json */
	if r.Method == "POST" {

		cid := util.GetCookie(r, "Uid")
		uid := HTMLEscapeString(r.FormValue("uid"))
		name := HTMLEscapeString(r.FormValue("name"))
		city := HTMLEscapeString(r.FormValue("city"))
		number := HTMLEscapeString(r.FormValue("number"))
jøè
Cfile:///home/flo/Desktop/Git/govwa/vulnerability/idor/idor.go:61-61G104Errors unhandled. 0:060: 	p := NewProfile()
61: 	p.GetData(sid)
62: 
BunknownbÎ	util.SafeRender(w, r, "template.idor1", data)

}

func idor2Handler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	session := session.New()
	sid := session.GetSession(r, "id")
	p := NewProfile()
	p.GetData(sid)

	data := make(map[string]interface{})
	signature := Md5Sum(sid)

	data["signature"] = signature
	data["title"] = "Insecure Direc Object References"
	data["uid"] = strconv.Itoa(p.Uid)
	data["name"] = p.Name
	data["city"] = p.City
	data["number"] = p.PhoneNumberjø±
Cfile:///home/flo/Desktop/Git/govwa/vulnerability/idor/idor.go:42-42G104Errors unhandled. 0:041: 	p := NewProfile()
42: 	p.GetData(sid)
43: 
Bunknownbçtype DataResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func idor1Handler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	session := session.New()
	sid := session.GetSession(r, "id")
	p := NewProfile()
	p.GetData(sid)

	data := make(map[string]interface{})

	data["title"] = "Insecure Direc Object References"
	data["uid"] = strconv.Itoa(p.Uid)
	data["name"] = p.Name
	data["city"] = p.City
	data["number"] = p.PhoneNumber

	util.SafeRender(w, r, "template.idor1", data)jø≥
9file:///home/flo/Desktop/Git/govwa/util/template.go:41-41G104Errors unhandled. 0:u40: 	template := template.Must(template.ParseGlob("templates/*"))
41: 	template.ExecuteTemplate(w, name, data)
42: }
Bunknownb‘		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func UnSafeRender(w http.ResponseWriter, name string, data ...interface{}) {

	template := template.Must(template.ParseGlob("templates/*"))
	template.ExecuteTemplate(w, name, data)
}

func ToHTML(text string)template.HTML{
	return template.HTML(text)
}jøÈ
9file:///home/flo/Desktop/Git/govwa/util/template.go:35-35G104Errors unhandled. 0:34: 	}
35: 	w.Write(b)
36: }
Bunknownb‚	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func UnSafeRender(w http.ResponseWriter, name string, data ...interface{}) {

	template := template.Must(template.ParseGlob("templates/*"))
	template.ExecuteTemplate(w, name, data)
}

func ToHTML(text string)template.HTML{
	return template.HTML(text)jøô
Ffile:///home/flo/Desktop/Git/govwa/util/middleware/middleware.go:71-71G104Errors unhandled. 0:s70: 			w.WriteHeader(http.StatusForbidden)
71: 			w.Write([]byte("Forbidden"))
72: 			log.Printf("sqlmap detect ")
BunknownbØ	}
}

func (this *Class) DetectSQLMap(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		userAgent := r.Header.Get("User-Agent")
		sqlmapDetected, _ := regexp.MatchString("sqlmap*", userAgent)
		if sqlmapDetected {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			log.Printf("sqlmap detect ")
			return
		} else {
			h(w, r, ps)
		}
	}
}jø