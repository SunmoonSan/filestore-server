package handler

import (
	"filestore-server/common"
	"filestore-server/util"
	"net/http"
)

// HTTPInterceptor 拦截器
func HTTPInterceptor(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			username := r.Form.Get("username")
			token := r.Form.Get("token")

			if len(username) < 3 || !IsTokenValid(token) {
				resp := util.NewRespMsg(
					int(common.StatusInvalidToken),
					"token无效",
					nil,
				)
				w.Write(resp.JSONBytes())
				return
			}
			h(w, r)
		})
}
