// Copyright (C) 2018 The Nori Authors info@nori.io
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
package main

import (

	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	cfg "github.com/nori-io/nori-common/config"

	"github.com/nori-io/nori-common/endpoint"
	"github.com/nori-io/nori-common/interfaces"
	"github.com/nori-io/nori-common/meta"
	noriPlugin "github.com/nori-io/nori-common/plugin"
)

type plugin struct {
	instance interfaces.Auth
	config   config
}

type instance struct {
	keyPublic  interface{}
	keyPrivate interface{}
	method     jwt.SigningMethod
	jwtIss     string
}

type config struct {
	jwtSignMethod cfg.String
	jwtKeyPublic  cfg.String
	jwtKeyPrivate cfg.String
	jwtIss        cfg.String
}

var (
	Plugin plugin

	errorTokenContextMissing     = errors.New("token up for parsing was not passed through the context")
	errorTokenInvalid            = errors.New("JWT Token was invalid")
	errorTokenExpired            = errors.New("JWT Token is expired")
	errorTokenMalformed          = errors.New("JWT Token is malformed")
	errorTokenNotActive          = errors.New("token is not valid yet")
	errorUnexpectedSigningMethod = errors.New("unexpected signing method")

	ErrPrivateKeyNotDefined = errors.New("private key not defined")
)

func (p *plugin) Init(_ context.Context, configManager cfg.Manager) error {
	cm := configManager.Register(p.Meta())
	p.config = config{
		jwtSignMethod: cm.String("jwt.signingMethod", "JWT signing method"),
		jwtKeyPublic:  cm.String("jwt.key.public", "Path to JWT public key file"),
		jwtKeyPrivate: cm.String("jwt.key.private", "Path to JWT private key file"),
		jwtIss:        cm.String("jwt.iss", "JWT iss value"),
	}
	return nil
}

func (p *plugin) Instance() interface{} {
	return p.instance
}

func (p plugin) Meta() meta.Meta {
	return &meta.Data{
		ID: meta.ID{
			ID:      "nori/auth/jwt",
			Version: "1.0.0",
		},
		Author: meta.Author{
			Name: "Nori",
			URI:  "https://nori.io",
		},
		Core: meta.Core{
			VersionConstraint: ">=1.0.0, <2.0.0",
		},
		Dependencies: []meta.Dependency{},
		Description: meta.Description{
			Name: "Nori: Auth Interface",
		},
		Interface: meta.Auth,
		License: meta.License{
			Title: "",
			Type:  "GPLv3",
			URI:   "https://www.gnu.org/licenses/"},
		Tags: []string{"auth", "nori", "core", "jwt"},
	}
}

func (p *plugin) Start(ctx context.Context, registry noriPlugin.Registry) error {
	if p.instance == nil {
		publicKey, err := ioutil.ReadFile(p.config.jwtKeyPublic())
		if err != nil {
			registry.Logger(p.Meta()).Error(err)
			return err
		}
		privateKey, err := ioutil.ReadFile(p.config.jwtKeyPrivate())
		if err != nil {
			registry.Logger(p.Meta()).Error(err)
			return err
		}

		var method jwt.SigningMethod
		switch strings.ToLower(p.config.jwtSignMethod()) {
		case "rs256":
			method = jwt.SigningMethodRS256
			break
		case "rs384":
			method = jwt.SigningMethodRS384
			break
		case "rs512":
			method = jwt.SigningMethodRS512
			break
		case "es256":
			method = jwt.SigningMethodES256
			break
		case "es384":
			method = jwt.SigningMethodES384
			break
		case "es512":
			method = jwt.SigningMethodES512
			break
		default:
			return errors.New("can't identify jwt signing method")
		}

		var pub, priv interface{}
		switch method.(type) {
		case *jwt.SigningMethodRSA:
			pub = parseRsaPublicKey(string(publicKey))
			priv = parsePsaPrivateKey(string(privateKey))
			break
		case *jwt.SigningMethodECDSA:
			pub = parseEcPublicKey(string(publicKey))
			priv = parseEcPrivateKey(string(privateKey))
			break
		}

		p.instance = &instance{
			method:     method,
			keyPublic:  pub,
			keyPrivate: priv,
			jwtIss:     p.config.jwtIss(),
		}
	}
	return nil
}

func (p *plugin) Stop(_ context.Context, _ noriPlugin.Registry) error {
	p.instance = nil
	return nil
}

func (i *instance) Authenticated() endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			tokenString, ok := ctx.Value(interfaces.AuthTokenContextKey).(string)
			if !ok {
				return nil, errorTokenContextMissing
			}

			token, err := jwt.ParseWithClaims(tokenString, i.newClaims(), func(token *jwt.Token) (interface{}, error) {
				if token.Method != i.method {
					return nil, errorUnexpectedSigningMethod
				}

				return i.keyFunc()(token)
			})
			if err != nil {
				if e, ok := err.(*jwt.ValidationError); ok {
					switch {
					case e.Errors&jwt.ValidationErrorMalformed != 0:
						// Token is malformed
						return nil, errorTokenMalformed
					case e.Errors&jwt.ValidationErrorExpired != 0:
						// Token is expired
						return nil, errorTokenExpired
					case e.Errors&jwt.ValidationErrorNotValidYet != 0:
						// Token is not active yet
						return nil, errorTokenNotActive
					case e.Inner != nil:
						// report e.Inner
						return nil, e.Inner
					}
				}
				return nil, err
			}

			if !token.Valid {
				return nil, errorTokenInvalid
			}

			ctx = context.WithValue(ctx, interfaces.AuthDataContextKey, token.Claims)

			return next(ctx, request)
		}
	}
}

func (i *instance) IsAuthenticated(ctx context.Context) bool {
	val := ctx.Value(interfaces.AuthDataContextKey)
	if _, ok := val.(instance); !ok {
		return false
	}
	return false
}

func (i *instance) AccessToken(ops interfaces.AccessTokenOption) (string, error) {
	if i.keyPrivate == nil {
		return "", ErrPrivateKeyNotDefined
	}

	jti := ops("jti")
	exp, ok := ops("exp").(time.Time)
	if !ok {
		exp = time.Now().Add(time.Hour * 72)
	}
	sub, ok := ops("sub").(string)
	if !ok {
		sub = ""
	}
	iss, ok := ops("iss").(string)
	if !ok {
		iss = "nori/auth"
	}
	nbf, ok := ops("nbf").(time.Time)
	if !ok {
		nbf = time.Now()
	}
	iat, ok := ops("iat").(time.Time)
	if !ok {
		iat = time.Now()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"jti": jti,
		"sub": sub,
		"iss": iss,
		"nbf": nbf.Unix(),
		"iat": iat.Unix(),
		"exp": exp.Unix(),
		"raw": ops("raw"),
	})

	// Sign and get the complete encoded token as a string using the secret
	jwt, err := token.SignedString(i.keyPrivate)
	if err != nil {
		return "", err
	}
	return jwt, nil
}

func (i *instance) keyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		return i.keyPublic, nil
	}
}

func (i *instance) signingMethod() jwt.SigningMethod {
	return i.method
}

func (i *instance) newClaims() jwt.Claims {
	return jwt.MapClaims{
		"iss": i.jwtIss,
	}
}

func parseRsaPublicKey(rsaPublicString string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(rsaPublicString))
	if block == nil {
		return nil
	}
	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil
	}
	pubkeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	rsaPublicKey, ok := pubkeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	return rsaPublicKey
}

func parsePsaPrivateKey(rsaPrivateString string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(rsaPrivateString))
	if block == nil {
		return nil
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil
	}
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	return rsaPrivateKey
}

func parseEcPublicKey(ecPublicString string) *ecdsa.PublicKey {
	// todo parse ec public key
	return nil
}

func parseEcPrivateKey(ecPrivateString string) *ecdsa.PrivateKey {
	// todo parse ec private key
	return nil
}
