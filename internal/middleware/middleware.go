package middleware

import "net/http"

type Middleware func(http.Handler) http.Handler

func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

func ChainFunc(h http.HandlerFunc, middlewares ...Middleware) http.Handler {
	return Chain(h, middlewares...)
}
