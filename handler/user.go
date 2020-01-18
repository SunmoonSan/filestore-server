package handler

import (
	dblayer "filestore-server/db"
	"filestore-server/util"
	"fmt"
	"net/http"
	"time"
)

const (
	// 用于加密的盐值(自定义)
	pwdSalt = "*#890"
)

// SignupHandler 处理用户注册请求
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/static/view/signup.html", http.StatusFound)
		return
	}
	r.ParseForm()

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	fmt.Println(username, password)

	if len(username) < 3 || len(password) < 5 {
		w.Write([]byte("Invalid params"))
		return
	}

	// 对密码进行加盐加密及去Sha1值加密
	encPasswd := util.Sha1([]byte(password + pwdSalt))
	// 将用户信息注册到用户表中
	suc := dblayer.UserSignup(username, encPasswd)
	if suc {
		w.Write([]byte("SUCCESS"))
	} else {
		w.Write([]byte("FAILED"))
	}
}

// SignInHandler 登录接口
func SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/static/view/signin.html", http.StatusFound)
		return
	}
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	encPasswd := util.Sha1([]byte(password + pwdSalt))

	// 1. 校验用户名和密码
	pwdChecked := dblayer.UserSignin(username, encPasswd)
	if !pwdChecked {
		w.Write([]byte("Failed"))
		return
	}

	// 2. 生成访问凭证(token)
	token := GenToken(username)
	upRes := dblayer.UpdateToken(username, token)
	if !upRes {
		w.Write([]byte("Failed"))
		return
	}

	// 3. 登录成功后重定向首页
	resp := util.RespMsg{
		Code: 0,
		Msg:  "OK",
		Data: struct {
			Location string
			Username string
			Token    string
		}{
			Location: "http://" + r.Host + "/static/view/home.html",
			Username: username,
			Token:    token,
		},
	}
	w.Write(resp.JSONBytes())
}

// UserInfoHandler 用户个人信息
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

// GenToken 生成Token
func GenToken(username string) string {
	ts := fmt.Sprintf("%x", time.Now().Unix())
	tokenPrefix := util.MD5([]byte(username + ts + "_tokensalt"))
	return tokenPrefix + ts[:8]
}

// IsTokenValid Token是否合法
func IsTokenValid(token string) bool {
	if len(token) != 40 {
		return false
	}
	return true
}
