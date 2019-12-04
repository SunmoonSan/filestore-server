package handler

import (
	dblayer "filestore-server/db"
	"filestore-server/util"
	"fmt"
	"net/http"
	"time"
)

const (
	pwdSalt = "*#890"
)

func SignupHandler(w http.ResponseWriter, r *http.Request)  {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/static/view/signup.html", http.StatusFound)
		return
	}
	r.ParseForm()

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if len(username) < 3 || len(password) < 5 {
		w.Write([]byte("Invalid params"))
		return
	}

	encPasswd := util.Sha1([]byte(password+pwdSalt))
	suc := dblayer.UserSignup(username, encPasswd)
	if suc {
		w.Write([]byte("Success"))
	} else {
		w.Write([]byte("Failed"))
	}
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/static/view/signin.html", http.StatusFound)
		return
	}
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	encPasswd := util.Sha1([]byte(password + pwdSalt))

	pwdChecked := dblayer.UserSignin(username, encPasswd)
	if !pwdChecked {
		w.Write([]byte("Failed"))
		return
	}

	token := GenToken(username)
	upRes := dblayer.UpdateToken(username, token)
	if !upRes {
		w.Write([]byte("Failed"))
		return
	}

	resp := util.RespMsg{
		Code: 0,
		Msg:  "OK",
		Data: struct {
			Location string
			Username string
			Token string
		}{
			Location: "http://" + r.Host + "/static/view/home.html",
			Username:username,
			Token:token,
		},
	}
	w.Write(resp.JSONBytes())
}

func UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.Form.Get("username")
	user, err := dblayer.GetUserInfo(username)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	resp := util.RespMsg{
		Code: 0,
		Msg:  "OK",
		Data: user,
	}
	w.Write(resp.JSONBytes())
}

func GenToken(username string) string {
	ts := fmt.Sprintf("%x", time.Now().Unix())
	tokenPrefix := util.MD5([]byte(username + ts + "_tokensalt"))
	return tokenPrefix + ts[:8]
}

func IsTokenValid(token string) bool {
	if len(token) != 40 {
		return false
	}
	return true
}
