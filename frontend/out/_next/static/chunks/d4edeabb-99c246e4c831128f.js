"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[440],{8577:function(a,b,c){c.d(b,{"$":function(){return a4},a5:function(){return a7},a6:function(){return a8},n:function(){return ci}});var d,e=c(4444),f=c(5816),g=c(655),h=c(3333),i=c(8463);function j(){return{"dependent-sdk-initialized-before-auth":"Another Firebase SDK was initialized and is trying to use Auth before Auth is initialized. Please be sure to call `initializeAuth` or `getAuth` before starting any other Firebase SDK."}}let k=j,l=new e.LL("auth","Firebase",j()),m=new h.Yd("@firebase/auth");function n(a,...b){m.logLevel<=h.in.ERROR&&m.error(`Auth (${f.Jn}): ${a}`,...b)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function o(a,...b){throw s(a,...b)}function p(a,...b){return s(a,...b)}function q(a,b,c){let d=Object.assign(Object.assign({},k()),{[b]:c}),f=new e.LL("auth","Firebase",d);return f.create(b,{appName:a.name})}function r(a,b,c){let d=c;if(!(b instanceof d))throw d.name!==b.constructor.name&&o(a,"argument-error"),q(a,"argument-error",`Type of ${b.constructor.name} does not match expected instance.Did you pass a reference from a different Auth SDK?`)}function s(a,...b){if("string"!=typeof a){let c=b[0],d=[...b.slice(1)];return d[0]&&(d[0].appName=a.name),a._errorFactory.create(c,...d)}return l.create(a,...b)}function t(a,b,...c){if(!a)throw s(b,...c)}function u(a){let b="INTERNAL ASSERTION FAILED: "+a;throw n(b),Error(b)}function v(a,b){a||u(b)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ let w=new Map;function x(a){v(a instanceof Function,"Expected a class definition");let b=w.get(a);return b?(v(b instanceof a,"Instance stored in cache mismatched with class"),b):(b=new a,w.set(a,b),b)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function y(){var a;return"undefined"!=typeof self&&(null===(a=self.location)|| void 0===a?void 0:a.href)||""}function z(){var a;return"undefined"!=typeof self&&(null===(a=self.location)|| void 0===a?void 0:a.protocol)||null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * A structure to help pick between a range of long and short delay durations
 * depending on the current environment. In general, the long delay is used for
 * mobile environments whereas short delays are used for desktop environments.
 */ class A{constructor(a,b){this.shortDelay=a,this.longDelay=b,v(b>a,"Short delay should be less than long delay!"),this.isMobile=(0,e.uI)()||(0,e.b$)()}get(){return!("undefined"!=typeof navigator&&navigator&&"onLine"in navigator&&"boolean"==typeof navigator.onLine&&("http:"===z()||"https:"===z()||(0,e.ru)()||"connection"in navigator))||navigator.onLine?this.isMobile?this.longDelay:this.shortDelay:Math.min(5e3,this.shortDelay)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function B(a,b){v(a.emulator,"Emulator should always be set here");let{url:c}=a.emulator;return b?`${c}${b.startsWith("/")?b.slice(1):b}`:c}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class C{static initialize(a,b,c){this.fetchImpl=a,b&&(this.headersImpl=b),c&&(this.responseImpl=c)}static fetch(){return this.fetchImpl?this.fetchImpl:"undefined"!=typeof self&&"fetch"in self?self.fetch:void u("Could not find fetch implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static headers(){return this.headersImpl?this.headersImpl:"undefined"!=typeof self&&"Headers"in self?self.Headers:void u("Could not find Headers implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static response(){return this.responseImpl?this.responseImpl:"undefined"!=typeof self&&"Response"in self?self.Response:void u("Could not find Response implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Map from errors returned by the server to errors to developer visible errors
 */ let D={CREDENTIAL_MISMATCH:"custom-token-mismatch",MISSING_CUSTOM_TOKEN:"internal-error",INVALID_IDENTIFIER:"invalid-email",MISSING_CONTINUE_URI:"internal-error",INVALID_PASSWORD:"wrong-password",MISSING_PASSWORD:"internal-error",EMAIL_EXISTS:"email-already-in-use",PASSWORD_LOGIN_DISABLED:"operation-not-allowed",INVALID_IDP_RESPONSE:"invalid-credential",INVALID_PENDING_TOKEN:"invalid-credential",FEDERATED_USER_ID_ALREADY_LINKED:"credential-already-in-use",MISSING_REQ_TYPE:"internal-error",EMAIL_NOT_FOUND:"user-not-found",RESET_PASSWORD_EXCEED_LIMIT:"too-many-requests",EXPIRED_OOB_CODE:"expired-action-code",INVALID_OOB_CODE:"invalid-action-code",MISSING_OOB_CODE:"internal-error",CREDENTIAL_TOO_OLD_LOGIN_AGAIN:"requires-recent-login",INVALID_ID_TOKEN:"invalid-user-token",TOKEN_EXPIRED:"user-token-expired",USER_NOT_FOUND:"user-token-expired",TOO_MANY_ATTEMPTS_TRY_LATER:"too-many-requests",INVALID_CODE:"invalid-verification-code",INVALID_SESSION_INFO:"invalid-verification-id",INVALID_TEMPORARY_PROOF:"invalid-credential",MISSING_SESSION_INFO:"missing-verification-id",SESSION_EXPIRED:"code-expired",MISSING_ANDROID_PACKAGE_NAME:"missing-android-pkg-name",UNAUTHORIZED_DOMAIN:"unauthorized-continue-uri",INVALID_OAUTH_CLIENT_ID:"invalid-oauth-client-id",ADMIN_ONLY_OPERATION:"admin-restricted-operation",INVALID_MFA_PENDING_CREDENTIAL:"invalid-multi-factor-session",MFA_ENROLLMENT_NOT_FOUND:"multi-factor-info-not-found",MISSING_MFA_ENROLLMENT_ID:"missing-multi-factor-info",MISSING_MFA_PENDING_CREDENTIAL:"missing-multi-factor-session",SECOND_FACTOR_EXISTS:"second-factor-already-in-use",SECOND_FACTOR_LIMIT_EXCEEDED:"maximum-second-factor-count-exceeded",BLOCKING_FUNCTION_ERROR_RESPONSE:"internal-error"},E=new A(3e4,6e4);function F(a,b){return a.tenantId&&!b.tenantId?Object.assign(Object.assign({},b),{tenantId:a.tenantId}):b}async function G(a,b,c,d,f={}){return H(a,f,async()=>{let f={},g={};d&&("GET"===b?g=d:f={body:JSON.stringify(d)});let h=(0,e.xO)(Object.assign({key:a.config.apiKey},g)).slice(1),i=await a._getAdditionalHeaders();return i["Content-Type"]="application/json",a.languageCode&&(i["X-Firebase-Locale"]=a.languageCode),C.fetch()(J(a,a.config.apiHost,c,h),Object.assign({method:b,headers:i,referrerPolicy:"no-referrer"},f))})}async function H(a,b,c){a._canInitEmulator=!1;let d=Object.assign(Object.assign({},D),b);try{let f=new K(a),g=await Promise.race([c(),f.promise]);f.clearNetworkTimeout();let h=await g.json();if("needConfirmation"in h)throw L(a,"account-exists-with-different-credential",h);if(g.ok&&!("errorMessage"in h))return h;{let i=g.ok?h.errorMessage:h.error.message,[j,k]=i.split(" : ");if("FEDERATED_USER_ID_ALREADY_LINKED"===j)throw L(a,"credential-already-in-use",h);if("EMAIL_EXISTS"===j)throw L(a,"email-already-in-use",h);if("USER_DISABLED"===j)throw L(a,"user-disabled",h);let l=d[j]||j.toLowerCase().replace(/[_\s]+/g,"-");if(k)throw q(a,l,k);o(a,l)}}catch(m){if(m instanceof e.ZR)throw m;o(a,"network-request-failed")}}async function I(a,b,c,d,e={}){let f=await G(a,b,c,d,e);return"mfaPendingCredential"in f&&o(a,"multi-factor-auth-required",{_serverResponse:f}),f}function J(a,b,c,d){let e=`${b}${c}?${d}`;return a.config.emulator?B(a.config,e):`${a.config.apiScheme}://${e}`}class K{constructor(a){this.auth=a,this.timer=null,this.promise=new Promise((a,b)=>{this.timer=setTimeout(()=>b(p(this.auth,"network-request-failed")),E.get())})}clearNetworkTimeout(){clearTimeout(this.timer)}}function L(a,b,c){let d={appName:a.name};c.email&&(d.email=c.email),c.phoneNumber&&(d.phoneNumber=c.phoneNumber);let e=p(a,b,d);return e.customData._tokenResponse=c,e}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function M(a,b){return G(a,"POST","/v1/accounts:delete",b)}async function N(a,b){return G(a,"POST","/v1/accounts:lookup",b)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function O(a){if(a)try{let b=new Date(Number(a));if(!isNaN(b.getTime()))return b.toUTCString()}catch(c){}}async function P(a,b=!1){let c=(0,e.m9)(a),d=await c.getIdToken(b),f=R(d);t(f&&f.exp&&f.auth_time&&f.iat,c.auth,"internal-error");let g="object"==typeof f.firebase?f.firebase:void 0,h=null==g?void 0:g.sign_in_provider;return{claims:f,token:d,authTime:O(Q(f.auth_time)),issuedAtTime:O(Q(f.iat)),expirationTime:O(Q(f.exp)),signInProvider:h||null,signInSecondFactor:(null==g?void 0:g.sign_in_second_factor)||null}}function Q(a){return 1e3*Number(a)}function R(a){var b;let[c,d,f]=a.split(".");if(void 0===c|| void 0===d|| void 0===f)return n("JWT malformed, contained fewer than 3 sections"),null;try{let g=(0,e.tV)(d);if(!g)return n("Failed to decode base64 JWT payload"),null;return JSON.parse(g)}catch(h){return n("Caught error parsing JWT payload as JSON",null===(b=h)|| void 0===b?void 0:b.toString()),null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function S(a,b,c=!1){if(c)return b;try{return await b}catch(d){throw d instanceof e.ZR&&T(d)&&a.auth.currentUser===a&&await a.auth.signOut(),d}}function T({code:a}){return"auth/user-disabled"===a||"auth/user-token-expired"===a}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class U{constructor(a,b){this.createdAt=a,this.lastLoginAt=b,this._initializeTime()}_initializeTime(){this.lastSignInTime=O(this.lastLoginAt),this.creationTime=O(this.createdAt)}_copy(a){this.createdAt=a.createdAt,this.lastLoginAt=a.lastLoginAt,this._initializeTime()}toJSON(){return{createdAt:this.createdAt,lastLoginAt:this.lastLoginAt}}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function V(a){var b;let c=a.auth,d=await a.getIdToken(),e=await S(a,N(c,{idToken:d}));t(null==e?void 0:e.users.length,c,"internal-error");let f=e.users[0];a._notifyReloadListener(f);let g=(null===(b=f.providerUserInfo)|| void 0===b?void 0:b.length)?Y(f.providerUserInfo):[],h=X(a.providerData,g),i=a.isAnonymous,j=!(a.email&&f.passwordHash)&&!(null==h?void 0:h.length),k={uid:f.localId,displayName:f.displayName||null,photoURL:f.photoUrl||null,email:f.email||null,emailVerified:f.emailVerified||!1,phoneNumber:f.phoneNumber||null,tenantId:f.tenantId||null,providerData:h,metadata:new U(f.createdAt,f.lastLoginAt),isAnonymous:!!i&&j};Object.assign(a,k)}async function W(a){let b=(0,e.m9)(a);await V(b),await b.auth._persistUserIfCurrent(b),b.auth._notifyListenersIfCurrent(b)}function X(a,b){let c=a.filter(a=>!b.some(b=>b.providerId===a.providerId));return[...c,...b]}function Y(a){return a.map(a=>{var{providerId:b}=a,c=(0,g._T)(a,["providerId"]);return{providerId:b,uid:c.rawId||"",displayName:c.displayName||null,email:c.email||null,phoneNumber:c.phoneNumber||null,photoURL:c.photoUrl||null}})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function Z(a,b){let c=await H(a,{},async()=>{let c=(0,e.xO)({grant_type:"refresh_token",refresh_token:b}).slice(1),{tokenApiHost:d,apiKey:f}=a.config,g=J(a,d,"/v1/token",`key=${f}`),h=await a._getAdditionalHeaders();return h["Content-Type"]="application/x-www-form-urlencoded",C.fetch()(g,{method:"POST",headers:h,body:c})});return{accessToken:c.access_token,expiresIn:c.expires_in,refreshToken:c.refresh_token}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * We need to mark this class as internal explicitly to exclude it in the public typings, because
 * it references AuthInternal which has a circular dependency with UserInternal.
 *
 * @internal
 */ class ${constructor(){this.refreshToken=null,this.accessToken=null,this.expirationTime=null}get isExpired(){return!this.expirationTime||Date.now()>this.expirationTime-3e4}updateFromServerResponse(a){t(a.idToken,"internal-error"),t(void 0!==a.idToken,"internal-error"),t(void 0!==a.refreshToken,"internal-error");let b="expiresIn"in a&& void 0!==a.expiresIn?Number(a.expiresIn):function(a){let b=R(a);return t(b,"internal-error"),t(void 0!==b.exp,"internal-error"),t(void 0!==b.iat,"internal-error"),Number(b.exp)-Number(b.iat)}(a.idToken);this.updateTokensAndExpiration(a.idToken,a.refreshToken,b)}async getToken(a,b=!1){return(t(!this.accessToken||this.refreshToken,a,"user-token-expired"),b||!this.accessToken||this.isExpired)?this.refreshToken?(await this.refresh(a,this.refreshToken),this.accessToken):null:this.accessToken}clearRefreshToken(){this.refreshToken=null}async refresh(a,b){let{accessToken:c,refreshToken:d,expiresIn:e}=await Z(a,b);this.updateTokensAndExpiration(c,d,Number(e))}updateTokensAndExpiration(a,b,c){this.refreshToken=b||null,this.accessToken=a||null,this.expirationTime=Date.now()+1e3*c}static fromJSON(a,b){let{refreshToken:c,accessToken:d,expirationTime:e}=b,f=new $;return c&&(t("string"==typeof c,"internal-error",{appName:a}),f.refreshToken=c),d&&(t("string"==typeof d,"internal-error",{appName:a}),f.accessToken=d),e&&(t("number"==typeof e,"internal-error",{appName:a}),f.expirationTime=e),f}toJSON(){return{refreshToken:this.refreshToken,accessToken:this.accessToken,expirationTime:this.expirationTime}}_assign(a){this.accessToken=a.accessToken,this.refreshToken=a.refreshToken,this.expirationTime=a.expirationTime}_clone(){return Object.assign(new $,this.toJSON())}_performRefresh(){return u("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function _(a,b){t("string"==typeof a|| void 0===a,"internal-error",{appName:b})}class aa{constructor(a){var{uid:b,auth:c,stsTokenManager:d}=a,e=(0,g._T)(a,["uid","auth","stsTokenManager"]);this.providerId="firebase",this.proactiveRefresh=new /**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class{constructor(a){this.user=a,this.isRunning=!1,this.timerId=null,this.errorBackoff=3e4}_start(){!this.isRunning&&(this.isRunning=!0,this.schedule())}_stop(){this.isRunning&&(this.isRunning=!1,null!==this.timerId&&clearTimeout(this.timerId))}getInterval(a){var b;if(a){let c=this.errorBackoff;return this.errorBackoff=Math.min(2*this.errorBackoff,96e4),c}{this.errorBackoff=3e4;let d=null!==(b=this.user.stsTokenManager.expirationTime)&& void 0!==b?b:0,e=d-Date.now()-3e5;return Math.max(0,e)}}schedule(a=!1){if(!this.isRunning)return;let b=this.getInterval(a);this.timerId=setTimeout(async()=>{await this.iteration()},b)}async iteration(){var a;try{await this.user.getIdToken(!0)}catch(b){(null===(a=b)|| void 0===a?void 0:a.code)==="auth/network-request-failed"&&this.schedule(!0);return}this.schedule()}}(this),this.reloadUserInfo=null,this.reloadListener=null,this.uid=b,this.auth=c,this.stsTokenManager=d,this.accessToken=d.accessToken,this.displayName=e.displayName||null,this.email=e.email||null,this.emailVerified=e.emailVerified||!1,this.phoneNumber=e.phoneNumber||null,this.photoURL=e.photoURL||null,this.isAnonymous=e.isAnonymous||!1,this.tenantId=e.tenantId||null,this.providerData=e.providerData?[...e.providerData]:[],this.metadata=new U(e.createdAt||void 0,e.lastLoginAt||void 0)}async getIdToken(a){let b=await S(this,this.stsTokenManager.getToken(this.auth,a));return t(b,this.auth,"internal-error"),this.accessToken!==b&&(this.accessToken=b,await this.auth._persistUserIfCurrent(this),this.auth._notifyListenersIfCurrent(this)),b}getIdTokenResult(a){return P(this,a)}reload(){return W(this)}_assign(a){this!==a&&(t(this.uid===a.uid,this.auth,"internal-error"),this.displayName=a.displayName,this.photoURL=a.photoURL,this.email=a.email,this.emailVerified=a.emailVerified,this.phoneNumber=a.phoneNumber,this.isAnonymous=a.isAnonymous,this.tenantId=a.tenantId,this.providerData=a.providerData.map(a=>Object.assign({},a)),this.metadata._copy(a.metadata),this.stsTokenManager._assign(a.stsTokenManager))}_clone(a){return new aa(Object.assign(Object.assign({},this),{auth:a,stsTokenManager:this.stsTokenManager._clone()}))}_onReload(a){t(!this.reloadListener,this.auth,"internal-error"),this.reloadListener=a,this.reloadUserInfo&&(this._notifyReloadListener(this.reloadUserInfo),this.reloadUserInfo=null)}_notifyReloadListener(a){this.reloadListener?this.reloadListener(a):this.reloadUserInfo=a}_startProactiveRefresh(){this.proactiveRefresh._start()}_stopProactiveRefresh(){this.proactiveRefresh._stop()}async _updateTokensIfNecessary(a,b=!1){let c=!1;a.idToken&&a.idToken!==this.stsTokenManager.accessToken&&(this.stsTokenManager.updateFromServerResponse(a),c=!0),b&&await V(this),await this.auth._persistUserIfCurrent(this),c&&this.auth._notifyListenersIfCurrent(this)}async delete(){let a=await this.getIdToken();return await S(this,M(this.auth,{idToken:a})),this.stsTokenManager.clearRefreshToken(),this.auth.signOut()}toJSON(){return Object.assign(Object.assign({uid:this.uid,email:this.email||void 0,emailVerified:this.emailVerified,displayName:this.displayName||void 0,isAnonymous:this.isAnonymous,photoURL:this.photoURL||void 0,phoneNumber:this.phoneNumber||void 0,tenantId:this.tenantId||void 0,providerData:this.providerData.map(a=>Object.assign({},a)),stsTokenManager:this.stsTokenManager.toJSON(),_redirectEventId:this._redirectEventId},this.metadata.toJSON()),{apiKey:this.auth.config.apiKey,appName:this.auth.name})}get refreshToken(){return this.stsTokenManager.refreshToken||""}static _fromJSON(a,b){var c,d,e,f,g,h,i,j;let k=null!==(c=b.displayName)&& void 0!==c?c:void 0,l=null!==(d=b.email)&& void 0!==d?d:void 0,m=null!==(e=b.phoneNumber)&& void 0!==e?e:void 0,n=null!==(f=b.photoURL)&& void 0!==f?f:void 0,o=null!==(g=b.tenantId)&& void 0!==g?g:void 0,p=null!==(h=b._redirectEventId)&& void 0!==h?h:void 0,q=null!==(i=b.createdAt)&& void 0!==i?i:void 0,r=null!==(j=b.lastLoginAt)&& void 0!==j?j:void 0,{uid:s,emailVerified:u,isAnonymous:v,providerData:w,stsTokenManager:x}=b;t(s&&x,a,"internal-error");let y=$.fromJSON(this.name,x);t("string"==typeof s,a,"internal-error"),_(k,a.name),_(l,a.name),t("boolean"==typeof u,a,"internal-error"),t("boolean"==typeof v,a,"internal-error"),_(m,a.name),_(n,a.name),_(o,a.name),_(p,a.name),_(q,a.name),_(r,a.name);let z=new aa({uid:s,auth:a,email:l,emailVerified:u,displayName:k,isAnonymous:v,photoURL:n,phoneNumber:m,tenantId:o,stsTokenManager:y,createdAt:q,lastLoginAt:r});return w&&Array.isArray(w)&&(z.providerData=w.map(a=>Object.assign({},a))),p&&(z._redirectEventId=p),z}static async _fromIdTokenResponse(a,b,c=!1){let d=new $;d.updateFromServerResponse(b);let e=new aa({uid:b.localId,auth:a,stsTokenManager:d,isAnonymous:c});return await V(e),e}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class ab{constructor(){this.type="NONE",this.storage={}}async _isAvailable(){return!0}async _set(a,b){this.storage[a]=b}async _get(a){let b=this.storage[a];return void 0===b?null:b}async _remove(a){delete this.storage[a]}_addListener(a,b){}_removeListener(a,b){}}ab.type="NONE";let ac=ab;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function ad(a,b,c){return`firebase:${a}:${b}:${c}`}class ae{constructor(a,b,c){this.persistence=a,this.auth=b,this.userKey=c;let{config:d,name:e}=this.auth;this.fullUserKey=ad(this.userKey,d.apiKey,e),this.fullPersistenceKey=ad("persistence",d.apiKey,e),this.boundEventHandler=b._onStorageEvent.bind(b),this.persistence._addListener(this.fullUserKey,this.boundEventHandler)}setCurrentUser(a){return this.persistence._set(this.fullUserKey,a.toJSON())}async getCurrentUser(){let a=await this.persistence._get(this.fullUserKey);return a?aa._fromJSON(this.auth,a):null}removeCurrentUser(){return this.persistence._remove(this.fullUserKey)}savePersistenceForRedirect(){return this.persistence._set(this.fullPersistenceKey,this.persistence.type)}async setPersistence(a){if(this.persistence===a)return;let b=await this.getCurrentUser();if(await this.removeCurrentUser(),this.persistence=a,b)return this.setCurrentUser(b)}delete(){this.persistence._removeListener(this.fullUserKey,this.boundEventHandler)}static async create(a,b,c="authUser"){if(!b.length)return new ae(x(ac),a,c);let d=(await Promise.all(b.map(async a=>{if(await a._isAvailable())return a}))).filter(a=>a),e=d[0]||x(ac),f=ad(c,a.config.apiKey,a.name),g=null;for(let h of b)try{let i=await h._get(f);if(i){let j=aa._fromJSON(a,i);h!==e&&(g=j),e=h;break}}catch(k){}let l=d.filter(a=>a._shouldAllowMigration);return e._shouldAllowMigration&&l.length&&(e=l[0],g&&await e._set(f,g.toJSON()),await Promise.all(b.map(async a=>{if(a!==e)try{await a._remove(f)}catch(b){}}))),new ae(e,a,c)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Determine the browser for the purposes of reporting usage to the API
 */ function af(a){let b=a.toLowerCase();if(b.includes("opera/")||b.includes("opr/")||b.includes("opios/"))return"Opera";if(aj(b))return"IEMobile";if(b.includes("msie")||b.includes("trident/"))return"IE";{if(b.includes("edge/"))return"Edge";if(ag(b))return"Firefox";if(b.includes("silk/"))return"Silk";if(al(b))return"Blackberry";if(am(b))return"Webos";if(ah(b))return"Safari";if((b.includes("chrome/")||ai(b))&&!b.includes("edge/"))return"Chrome";if(ak(b))return"Android";let c=/([a-zA-Z\d\.]+)\/[a-zA-Z\d\.]*$/,d=a.match(c);if((null==d?void 0:d.length)===2)return d[1]}return"Other"}function ag(a=(0,e.z$)()){return/firefox\//i.test(a)}function ah(a=(0,e.z$)()){let b=a.toLowerCase();return b.includes("safari/")&&!b.includes("chrome/")&&!b.includes("crios/")&&!b.includes("android")}function ai(a=(0,e.z$)()){return/crios\//i.test(a)}function aj(a=(0,e.z$)()){return/iemobile/i.test(a)}function ak(a=(0,e.z$)()){return/android/i.test(a)}function al(a=(0,e.z$)()){return/blackberry/i.test(a)}function am(a=(0,e.z$)()){return/webos/i.test(a)}function an(a=(0,e.z$)()){return/iphone|ipad|ipod/i.test(a)||/macintosh/i.test(a)&&/mobile/i.test(a)}function ao(a=(0,e.z$)()){return an(a)||ak(a)||am(a)||al(a)||/windows phone/i.test(a)||aj(a)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /*
 * Determine the SDK version string
 */ function ap(a,b=[]){let c;switch(a){case"Browser":c=af((0,e.z$)());break;case"Worker":c=`${af((0,e.z$)())}-${a}`;break;default:c=a}let d=b.length?b.join(","):"FirebaseCore-web";return`${c}/JsCore/${f.Jn}/${d}`}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class aq{constructor(a,b,c){this.app=a,this.heartbeatServiceProvider=b,this.config=c,this.currentUser=null,this.emulatorConfig=null,this.operations=Promise.resolve(),this.authStateSubscription=new as(this),this.idTokenSubscription=new as(this),this.beforeStateQueue=new /**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class{constructor(a){this.auth=a,this.queue=[]}pushCallback(a,b){let c=b=>new Promise((c,d)=>{try{let e=a(b);c(e)}catch(f){d(f)}});c.onAbort=b,this.queue.push(c);let d=this.queue.length-1;return()=>{this.queue[d]=()=>Promise.resolve()}}async runMiddleware(a){var b;if(this.auth.currentUser===a)return;let c=[];try{for(let d of this.queue)await d(a),d.onAbort&&c.push(d.onAbort)}catch(e){for(let f of(c.reverse(),c))try{f()}catch(g){}throw this.auth._errorFactory.create("login-blocked",{originalMessage:null===(b=e)|| void 0===b?void 0:b.message})}}}(this),this.redirectUser=null,this.isProactiveRefreshEnabled=!1,this._canInitEmulator=!0,this._isInitialized=!1,this._deleted=!1,this._initializationPromise=null,this._popupRedirectResolver=null,this._errorFactory=l,this.lastNotifiedUid=void 0,this.languageCode=null,this.tenantId=null,this.settings={appVerificationDisabledForTesting:!1},this.frameworks=[],this.name=a.name,this.clientVersion=c.sdkClientVersion}_initializeWithPersistence(a,b){return b&&(this._popupRedirectResolver=x(b)),this._initializationPromise=this.queue(async()=>{var c,d;if(!this._deleted&&(this.persistenceManager=await ae.create(this,a),!this._deleted)){if(null===(c=this._popupRedirectResolver)|| void 0===c?void 0:c._shouldInitProactively)try{await this._popupRedirectResolver._initialize(this)}catch(e){}await this.initializeCurrentUser(b),this.lastNotifiedUid=(null===(d=this.currentUser)|| void 0===d?void 0:d.uid)||null,!this._deleted&&(this._isInitialized=!0)}}),this._initializationPromise}async _onStorageEvent(){if(this._deleted)return;let a=await this.assertedPersistence.getCurrentUser();if(this.currentUser||a){if(this.currentUser&&a&&this.currentUser.uid===a.uid){this._currentUser._assign(a),await this.currentUser.getIdToken();return}await this._updateCurrentUser(a,!0)}}async initializeCurrentUser(a){var b;let c=await this.assertedPersistence.getCurrentUser(),d=c,e=!1;if(a&&this.config.authDomain){await this.getOrInitRedirectPersistenceManager();let f=null===(b=this.redirectUser)|| void 0===b?void 0:b._redirectEventId,g=null==d?void 0:d._redirectEventId,h=await this.tryRedirectSignIn(a);(!f||f===g)&&(null==h?void 0:h.user)&&(d=h.user,e=!0)}if(!d)return this.directlySetCurrentUser(null);if(!d._redirectEventId){if(e)try{await this.beforeStateQueue.runMiddleware(d)}catch(i){d=c,this._popupRedirectResolver._overrideRedirectResult(this,()=>Promise.reject(i))}return d?this.reloadAndSetCurrentUserOrClear(d):this.directlySetCurrentUser(null)}return(t(this._popupRedirectResolver,this,"argument-error"),await this.getOrInitRedirectPersistenceManager(),this.redirectUser&&this.redirectUser._redirectEventId===d._redirectEventId)?this.directlySetCurrentUser(d):this.reloadAndSetCurrentUserOrClear(d)}async tryRedirectSignIn(a){let b=null;try{b=await this._popupRedirectResolver._completeRedirectFn(this,a,!0)}catch(c){await this._setRedirectUser(null)}return b}async reloadAndSetCurrentUserOrClear(a){var b;try{await V(a)}catch(c){if((null===(b=c)|| void 0===b?void 0:b.code)!=="auth/network-request-failed")return this.directlySetCurrentUser(null)}return this.directlySetCurrentUser(a)}useDeviceLanguage(){this.languageCode=function(){if("undefined"==typeof navigator)return null;let a=navigator;return a.languages&&a.languages[0]||a.language||null}()}async _delete(){this._deleted=!0}async updateCurrentUser(a){let b=a?(0,e.m9)(a):null;return b&&t(b.auth.config.apiKey===this.config.apiKey,this,"invalid-user-token"),this._updateCurrentUser(b&&b._clone(this))}async _updateCurrentUser(a,b=!1){if(!this._deleted)return a&&t(this.tenantId===a.tenantId,this,"tenant-id-mismatch"),b||await this.beforeStateQueue.runMiddleware(a),this.queue(async()=>{await this.directlySetCurrentUser(a),this.notifyAuthListeners()})}async signOut(){return await this.beforeStateQueue.runMiddleware(null),(this.redirectPersistenceManager||this._popupRedirectResolver)&&await this._setRedirectUser(null),this._updateCurrentUser(null,!0)}setPersistence(a){return this.queue(async()=>{await this.assertedPersistence.setPersistence(x(a))})}_getPersistence(){return this.assertedPersistence.persistence.type}_updateErrorMap(a){this._errorFactory=new e.LL("auth","Firebase",a())}onAuthStateChanged(a,b,c){return this.registerStateListener(this.authStateSubscription,a,b,c)}beforeAuthStateChanged(a,b){return this.beforeStateQueue.pushCallback(a,b)}onIdTokenChanged(a,b,c){return this.registerStateListener(this.idTokenSubscription,a,b,c)}toJSON(){var a;return{apiKey:this.config.apiKey,authDomain:this.config.authDomain,appName:this.name,currentUser:null===(a=this._currentUser)|| void 0===a?void 0:a.toJSON()}}async _setRedirectUser(a,b){let c=await this.getOrInitRedirectPersistenceManager(b);return null===a?c.removeCurrentUser():c.setCurrentUser(a)}async getOrInitRedirectPersistenceManager(a){if(!this.redirectPersistenceManager){let b=a&&x(a)||this._popupRedirectResolver;t(b,this,"argument-error"),this.redirectPersistenceManager=await ae.create(this,[x(b._redirectPersistence)],"redirectUser"),this.redirectUser=await this.redirectPersistenceManager.getCurrentUser()}return this.redirectPersistenceManager}async _redirectUserForId(a){var b,c;return(this._isInitialized&&await this.queue(async()=>{}),(null===(b=this._currentUser)|| void 0===b?void 0:b._redirectEventId)===a)?this._currentUser:(null===(c=this.redirectUser)|| void 0===c?void 0:c._redirectEventId)===a?this.redirectUser:null}async _persistUserIfCurrent(a){if(a===this.currentUser)return this.queue(async()=>this.directlySetCurrentUser(a))}_notifyListenersIfCurrent(a){a===this.currentUser&&this.notifyAuthListeners()}_key(){return`${this.config.authDomain}:${this.config.apiKey}:${this.name}`}_startProactiveRefresh(){this.isProactiveRefreshEnabled=!0,this.currentUser&&this._currentUser._startProactiveRefresh()}_stopProactiveRefresh(){this.isProactiveRefreshEnabled=!1,this.currentUser&&this._currentUser._stopProactiveRefresh()}get _currentUser(){return this.currentUser}notifyAuthListeners(){var a,b;if(!this._isInitialized)return;this.idTokenSubscription.next(this.currentUser);let c=null!==(b=null===(a=this.currentUser)|| void 0===a?void 0:a.uid)&& void 0!==b?b:null;this.lastNotifiedUid!==c&&(this.lastNotifiedUid=c,this.authStateSubscription.next(this.currentUser))}registerStateListener(a,b,c,d){if(this._deleted)return()=>{};let e="function"==typeof b?b:b.next.bind(b),f=this._isInitialized?Promise.resolve():this._initializationPromise;return(t(f,this,"internal-error"),f.then(()=>e(this.currentUser)),"function"==typeof b)?a.addObserver(b,c,d):a.addObserver(b)}async directlySetCurrentUser(a){this.currentUser&&this.currentUser!==a&&(this._currentUser._stopProactiveRefresh(),a&&this.isProactiveRefreshEnabled&&a._startProactiveRefresh()),this.currentUser=a,a?await this.assertedPersistence.setCurrentUser(a):await this.assertedPersistence.removeCurrentUser()}queue(a){return this.operations=this.operations.then(a,a),this.operations}get assertedPersistence(){return t(this.persistenceManager,this,"internal-error"),this.persistenceManager}_logFramework(a){!(!a||this.frameworks.includes(a))&&(this.frameworks.push(a),this.frameworks.sort(),this.clientVersion=ap(this.config.clientPlatform,this._getFrameworks()))}_getFrameworks(){return this.frameworks}async _getAdditionalHeaders(){var a;let b={"X-Client-Version":this.clientVersion};this.app.options.appId&&(b["X-Firebase-gmpid"]=this.app.options.appId);let c=await (null===(a=this.heartbeatServiceProvider.getImmediate({optional:!0}))|| void 0===a?void 0:a.getHeartbeatsHeader());return c&&(b["X-Firebase-Client"]=c),b}}function ar(a){return(0,e.m9)(a)}class as{constructor(a){this.auth=a,this.observer=null,this.addObserver=(0,e.ne)(a=>this.observer=a)}get next(){return t(this.observer,this.auth,"internal-error"),this.observer.next.bind(this.observer)}}function at(a){if(!a)return null;let b=Number(a);return isNaN(b)?null:b}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Interface that represents the credentials returned by an {@link AuthProvider}.
 *
 * @remarks
 * Implementations specify the details about each auth provider's credential requirements.
 *
 * @public
 */ class au{constructor(a,b){this.providerId=a,this.signInMethod=b}toJSON(){return u("not implemented")}_getIdTokenResponse(a){return u("not implemented")}_linkToIdToken(a,b){return u("not implemented")}_getReauthenticationResolver(a){return u("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function av(a,b){return G(a,"POST","/v1/accounts:resetPassword",F(a,b))}async function aw(a,b){return G(a,"POST","/v1/accounts:update",b)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function ax(a,b){return I(a,"POST","/v1/accounts:signInWithPassword",F(a,b))}async function ay(a,b){return G(a,"POST","/v1/accounts:sendOobCode",F(a,b))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function az(a,b){return I(a,"POST","/v1/accounts:signInWithEmailLink",F(a,b))}async function aA(a,b){return I(a,"POST","/v1/accounts:signInWithEmailLink",F(a,b))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Interface that represents the credentials returned by {@link EmailAuthProvider} for
 * {@link ProviderId}.PASSWORD
 *
 * @remarks
 * Covers both {@link SignInMethod}.EMAIL_PASSWORD and
 * {@link SignInMethod}.EMAIL_LINK.
 *
 * @public
 */ class aB extends au{constructor(a,b,c,d=null){super("password",c),this._email=a,this._password=b,this._tenantId=d}static _fromEmailAndPassword(a,b){return new aB(a,b,"password")}static _fromEmailAndCode(a,b,c=null){return new aB(a,b,"emailLink",c)}toJSON(){return{email:this._email,password:this._password,signInMethod:this.signInMethod,tenantId:this._tenantId}}static fromJSON(a){let b="string"==typeof a?JSON.parse(a):a;if((null==b?void 0:b.email)&&(null==b?void 0:b.password)){if("password"===b.signInMethod)return this._fromEmailAndPassword(b.email,b.password);if("emailLink"===b.signInMethod)return this._fromEmailAndCode(b.email,b.password,b.tenantId)}return null}async _getIdTokenResponse(a){switch(this.signInMethod){case"password":return ax(a,{returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return az(a,{email:this._email,oobCode:this._password});default:o(a,"internal-error")}}async _linkToIdToken(a,b){switch(this.signInMethod){case"password":return aw(a,{idToken:b,returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return aA(a,{idToken:b,email:this._email,oobCode:this._password});default:o(a,"internal-error")}}_getReauthenticationResolver(a){return this._getIdTokenResponse(a)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function aC(a,b){return I(a,"POST","/v1/accounts:signInWithIdp",F(a,b))}class aD extends au{constructor(){super(...arguments),this.pendingToken=null}static _fromParams(a){let b=new aD(a.providerId,a.signInMethod);return a.idToken||a.accessToken?(a.idToken&&(b.idToken=a.idToken),a.accessToken&&(b.accessToken=a.accessToken),a.nonce&&!a.pendingToken&&(b.nonce=a.nonce),a.pendingToken&&(b.pendingToken=a.pendingToken)):a.oauthToken&&a.oauthTokenSecret?(b.accessToken=a.oauthToken,b.secret=a.oauthTokenSecret):o("argument-error"),b}toJSON(){return{idToken:this.idToken,accessToken:this.accessToken,secret:this.secret,nonce:this.nonce,pendingToken:this.pendingToken,providerId:this.providerId,signInMethod:this.signInMethod}}static fromJSON(a){let b="string"==typeof a?JSON.parse(a):a,{providerId:c,signInMethod:d}=b,e=(0,g._T)(b,["providerId","signInMethod"]);if(!c||!d)return null;let f=new aD(c,d);return f.idToken=e.idToken||void 0,f.accessToken=e.accessToken||void 0,f.secret=e.secret,f.nonce=e.nonce,f.pendingToken=e.pendingToken||null,f}_getIdTokenResponse(a){let b=this.buildRequest();return aC(a,b)}_linkToIdToken(a,b){let c=this.buildRequest();return c.idToken=b,aC(a,c)}_getReauthenticationResolver(a){let b=this.buildRequest();return b.autoCreate=!1,aC(a,b)}buildRequest(){let a={requestUri:"http://localhost",returnSecureToken:!0};if(this.pendingToken)a.pendingToken=this.pendingToken;else{let b={};this.idToken&&(b.id_token=this.idToken),this.accessToken&&(b.access_token=this.accessToken),this.secret&&(b.oauth_token_secret=this.secret),b.providerId=this.providerId,this.nonce&&!this.pendingToken&&(b.nonce=this.nonce),a.postBody=(0,e.xO)(b)}return a}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function aE(a,b){return G(a,"POST","/v1/accounts:sendVerificationCode",F(a,b))}async function aF(a,b){return I(a,"POST","/v1/accounts:signInWithPhoneNumber",F(a,b))}async function aG(a,b){let c=await I(a,"POST","/v1/accounts:signInWithPhoneNumber",F(a,b));if(c.temporaryProof)throw L(a,"account-exists-with-different-credential",c);return c}let aH={USER_NOT_FOUND:"user-not-found"};async function aI(a,b){let c=Object.assign(Object.assign({},b),{operation:"REAUTH"});return I(a,"POST","/v1/accounts:signInWithPhoneNumber",F(a,c),aH)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Represents the credentials returned by {@link PhoneAuthProvider}.
 *
 * @public
 */ class aJ extends au{constructor(a){super("phone","phone"),this.params=a}static _fromVerification(a,b){return new aJ({verificationId:a,verificationCode:b})}static _fromTokenResponse(a,b){return new aJ({phoneNumber:a,temporaryProof:b})}_getIdTokenResponse(a){return aF(a,this._makeVerificationRequest())}_linkToIdToken(a,b){return aG(a,Object.assign({idToken:b},this._makeVerificationRequest()))}_getReauthenticationResolver(a){return aI(a,this._makeVerificationRequest())}_makeVerificationRequest(){let{temporaryProof:a,phoneNumber:b,verificationId:c,verificationCode:d}=this.params;return a&&b?{temporaryProof:a,phoneNumber:b}:{sessionInfo:c,code:d}}toJSON(){let a={providerId:this.providerId};return this.params.phoneNumber&&(a.phoneNumber=this.params.phoneNumber),this.params.temporaryProof&&(a.temporaryProof=this.params.temporaryProof),this.params.verificationCode&&(a.verificationCode=this.params.verificationCode),this.params.verificationId&&(a.verificationId=this.params.verificationId),a}static fromJSON(a){"string"==typeof a&&(a=JSON.parse(a));let{verificationId:b,verificationCode:c,phoneNumber:d,temporaryProof:e}=a;return c||b||d||e?new aJ({verificationId:b,verificationCode:c,phoneNumber:d,temporaryProof:e}):null}}class aK{constructor(a){var b,c,d,f,g,h;let i=(0,e.zd)((0,e.pd)(a)),j=null!==(b=i.apiKey)&& void 0!==b?b:null,k=null!==(c=i.oobCode)&& void 0!==c?c:null,l=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Maps the mode string in action code URL to Action Code Info operation.
 *
 * @param mode
 */ function(a){switch(a){case"recoverEmail":return"RECOVER_EMAIL";case"resetPassword":return"PASSWORD_RESET";case"signIn":return"EMAIL_SIGNIN";case"verifyEmail":return"VERIFY_EMAIL";case"verifyAndChangeEmail":return"VERIFY_AND_CHANGE_EMAIL";case"revertSecondFactorAddition":return"REVERT_SECOND_FACTOR_ADDITION";default:return null}}(null!==(d=i.mode)&& void 0!==d?d:null);t(j&&k&&l,"argument-error"),this.apiKey=j,this.operation=l,this.code=k,this.continueUrl=null!==(f=i.continueUrl)&& void 0!==f?f:null,this.languageCode=null!==(g=i.languageCode)&& void 0!==g?g:null,this.tenantId=null!==(h=i.tenantId)&& void 0!==h?h:null}static parseLink(a){let b=function(a){let b=(0,e.zd)((0,e.pd)(a)).link,c=b?(0,e.zd)((0,e.pd)(b)).deep_link_id:null,d=(0,e.zd)((0,e.pd)(a)).deep_link_id,f=d?(0,e.zd)((0,e.pd)(d)).link:null;return f||d||c||b||a}(a);try{return new aK(b)}catch(c){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Provider for generating {@link EmailAuthCredential}.
 *
 * @public
 */ class aL{constructor(){this.providerId=aL.PROVIDER_ID}static credential(a,b){return aB._fromEmailAndPassword(a,b)}static credentialWithLink(a,b){let c=aK.parseLink(b);return t(c,"argument-error"),aB._fromEmailAndCode(a,c.code,c.tenantId)}}aL.PROVIDER_ID="password",aL.EMAIL_PASSWORD_SIGN_IN_METHOD="password",aL.EMAIL_LINK_SIGN_IN_METHOD="emailLink";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * The base class for all Federated providers (OAuth (including OIDC), SAML).
 *
 * This class is not meant to be instantiated directly.
 *
 * @public
 */ class aM{constructor(a){this.providerId=a,this.defaultLanguageCode=null,this.customParameters={}}setDefaultLanguage(a){this.defaultLanguageCode=a}setCustomParameters(a){return this.customParameters=a,this}getCustomParameters(){return this.customParameters}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Common code to all OAuth providers. This is separate from the
 * {@link OAuthProvider} so that child providers (like
 * {@link GoogleAuthProvider}) don't inherit the `credential` instance method.
 * Instead, they rely on a static `credential` method.
 */ class aN extends aM{constructor(){super(...arguments),this.scopes=[]}addScope(a){return this.scopes.includes(a)||this.scopes.push(a),this}getScopes(){return[...this.scopes]}}class aO extends null{static credentialFromJSON(a){let b="string"==typeof a?JSON.parse(a):a;return t("providerId"in b&&"signInMethod"in b,"argument-error"),aD._fromParams(b)}credential(a){return this._credential(Object.assign(Object.assign({},a),{nonce:a.rawNonce}))}_credential(a){return t(a.idToken||a.accessToken,"argument-error"),aD._fromParams(Object.assign(Object.assign({},a),{providerId:this.providerId,signInMethod:this.providerId}))}static credentialFromResult(a){return aO.oauthCredentialFromTaggedObject(a)}static credentialFromError(a){return aO.oauthCredentialFromTaggedObject(a.customData||{})}static oauthCredentialFromTaggedObject({_tokenResponse:a}){if(!a)return null;let{oauthIdToken:b,oauthAccessToken:c,oauthTokenSecret:d,pendingToken:e,nonce:f,providerId:g}=a;if(!c&&!d&&!b&&!e||!g)return null;try{return new aO(g)._credential({idToken:b,accessToken:c,nonce:f,pendingToken:e})}catch(h){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Provider for generating an {@link OAuthCredential} for {@link ProviderId}.FACEBOOK.
 *
 * @example
 * ```javascript
 * // Sign in using a redirect.
 * const provider = new FacebookAuthProvider();
 * // Start a sign in process for an unauthenticated user.
 * provider.addScope('user_birthday');
 * await signInWithRedirect(auth, provider);
 * // This will trigger a full page redirect away from your app
 *
 * // After returning from the redirect when your app initializes you can obtain the result
 * const result = await getRedirectResult(auth);
 * if (result) {
 *   // This is the signed-in user
 *   const user = result.user;
 *   // This gives you a Facebook Access Token.
 *   const credential = FacebookAuthProvider.credentialFromResult(result);
 *   const token = credential.accessToken;
 * }
 * ```
 *
 * @example
 * ```javascript
 * // Sign in using a popup.
 * const provider = new FacebookAuthProvider();
 * provider.addScope('user_birthday');
 * const result = await signInWithPopup(auth, provider);
 *
 * // The signed-in user info.
 * const user = result.user;
 * // This gives you a Facebook Access Token.
 * const credential = FacebookAuthProvider.credentialFromResult(result);
 * const token = credential.accessToken;
 * ```
 *
 * @public
 */ class aP extends aN{constructor(){super("facebook.com")}static credential(a){return aD._fromParams({providerId:aP.PROVIDER_ID,signInMethod:aP.FACEBOOK_SIGN_IN_METHOD,accessToken:a})}static credentialFromResult(a){return aP.credentialFromTaggedObject(a)}static credentialFromError(a){return aP.credentialFromTaggedObject(a.customData||{})}static credentialFromTaggedObject({_tokenResponse:a}){if(!a||!("oauthAccessToken"in a)||!a.oauthAccessToken)return null;try{return aP.credential(a.oauthAccessToken)}catch(b){return null}}}aP.FACEBOOK_SIGN_IN_METHOD="facebook.com",aP.PROVIDER_ID="facebook.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Provider for generating an an {@link OAuthCredential} for {@link ProviderId}.GOOGLE.
 *
 * @example
 * ```javascript
 * // Sign in using a redirect.
 * const provider = new GoogleAuthProvider();
 * // Start a sign in process for an unauthenticated user.
 * provider.addScope('profile');
 * provider.addScope('email');
 * await signInWithRedirect(auth, provider);
 * // This will trigger a full page redirect away from your app
 *
 * // After returning from the redirect when your app initializes you can obtain the result
 * const result = await getRedirectResult(auth);
 * if (result) {
 *   // This is the signed-in user
 *   const user = result.user;
 *   // This gives you a Google Access Token.
 *   const credential = GoogleAuthProvider.credentialFromResult(result);
 *   const token = credential.accessToken;
 * }
 * ```
 *
 * @example
 * ```javascript
 * // Sign in using a popup.
 * const provider = new GoogleAuthProvider();
 * provider.addScope('profile');
 * provider.addScope('email');
 * const result = await signInWithPopup(auth, provider);
 *
 * // The signed-in user info.
 * const user = result.user;
 * // This gives you a Google Access Token.
 * const credential = GoogleAuthProvider.credentialFromResult(result);
 * const token = credential.accessToken;
 * ```
 *
 * @public
 */ class aQ extends aN{constructor(){super("google.com"),this.addScope("profile")}static credential(a,b){return aD._fromParams({providerId:aQ.PROVIDER_ID,signInMethod:aQ.GOOGLE_SIGN_IN_METHOD,idToken:a,accessToken:b})}static credentialFromResult(a){return aQ.credentialFromTaggedObject(a)}static credentialFromError(a){return aQ.credentialFromTaggedObject(a.customData||{})}static credentialFromTaggedObject({_tokenResponse:a}){if(!a)return null;let{oauthIdToken:b,oauthAccessToken:c}=a;if(!b&&!c)return null;try{return aQ.credential(b,c)}catch(d){return null}}}aQ.GOOGLE_SIGN_IN_METHOD="google.com",aQ.PROVIDER_ID="google.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Provider for generating an {@link OAuthCredential} for {@link ProviderId}.GITHUB.
 *
 * @remarks
 * GitHub requires an OAuth 2.0 redirect, so you can either handle the redirect directly, or use
 * the {@link signInWithPopup} handler:
 *
 * @example
 * ```javascript
 * // Sign in using a redirect.
 * const provider = new GithubAuthProvider();
 * // Start a sign in process for an unauthenticated user.
 * provider.addScope('repo');
 * await signInWithRedirect(auth, provider);
 * // This will trigger a full page redirect away from your app
 *
 * // After returning from the redirect when your app initializes you can obtain the result
 * const result = await getRedirectResult(auth);
 * if (result) {
 *   // This is the signed-in user
 *   const user = result.user;
 *   // This gives you a Github Access Token.
 *   const credential = GithubAuthProvider.credentialFromResult(result);
 *   const token = credential.accessToken;
 * }
 * ```
 *
 * @example
 * ```javascript
 * // Sign in using a popup.
 * const provider = new GithubAuthProvider();
 * provider.addScope('repo');
 * const result = await signInWithPopup(auth, provider);
 *
 * // The signed-in user info.
 * const user = result.user;
 * // This gives you a Github Access Token.
 * const credential = GithubAuthProvider.credentialFromResult(result);
 * const token = credential.accessToken;
 * ```
 * @public
 */ class aR extends aN{constructor(){super("github.com")}static credential(a){return aD._fromParams({providerId:aR.PROVIDER_ID,signInMethod:aR.GITHUB_SIGN_IN_METHOD,accessToken:a})}static credentialFromResult(a){return aR.credentialFromTaggedObject(a)}static credentialFromError(a){return aR.credentialFromTaggedObject(a.customData||{})}static credentialFromTaggedObject({_tokenResponse:a}){if(!a||!("oauthAccessToken"in a)||!a.oauthAccessToken)return null;try{return aR.credential(a.oauthAccessToken)}catch(b){return null}}}aR.GITHUB_SIGN_IN_METHOD="github.com",aR.PROVIDER_ID="github.com";class aS extends null{constructor(a,b){super(a,a),this.pendingToken=b}_getIdTokenResponse(a){let b=this.buildRequest();return aC(a,b)}_linkToIdToken(a,b){let c=this.buildRequest();return c.idToken=b,aC(a,c)}_getReauthenticationResolver(a){let b=this.buildRequest();return b.autoCreate=!1,aC(a,b)}toJSON(){return{signInMethod:this.signInMethod,providerId:this.providerId,pendingToken:this.pendingToken}}static fromJSON(a){let b="string"==typeof a?JSON.parse(a):a,{providerId:c,signInMethod:d,pendingToken:e}=b;return c&&d&&e&&c===d?new aS(c,e):null}static _create(a,b){return new aS(a,b)}buildRequest(){return{requestUri:"http://localhost",returnSecureToken:!0,pendingToken:this.pendingToken}}}class aT extends null{constructor(a){t(a.startsWith("saml."),"argument-error"),super(a)}static credentialFromResult(a){return aT.samlCredentialFromTaggedObject(a)}static credentialFromError(a){return aT.samlCredentialFromTaggedObject(a.customData||{})}static credentialFromJSON(a){let b=aS.fromJSON(a);return t(b,"argument-error"),b}static samlCredentialFromTaggedObject({_tokenResponse:a}){if(!a)return null;let{pendingToken:b,providerId:c}=a;if(!b||!c)return null;try{return aS._create(c,b)}catch(d){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Provider for generating an {@link OAuthCredential} for {@link ProviderId}.TWITTER.
 *
 * @example
 * ```javascript
 * // Sign in using a redirect.
 * const provider = new TwitterAuthProvider();
 * // Start a sign in process for an unauthenticated user.
 * await signInWithRedirect(auth, provider);
 * // This will trigger a full page redirect away from your app
 *
 * // After returning from the redirect when your app initializes you can obtain the result
 * const result = await getRedirectResult(auth);
 * if (result) {
 *   // This is the signed-in user
 *   const user = result.user;
 *   // This gives you a Twitter Access Token and Secret.
 *   const credential = TwitterAuthProvider.credentialFromResult(result);
 *   const token = credential.accessToken;
 *   const secret = credential.secret;
 * }
 * ```
 *
 * @example
 * ```javascript
 * // Sign in using a popup.
 * const provider = new TwitterAuthProvider();
 * const result = await signInWithPopup(auth, provider);
 *
 * // The signed-in user info.
 * const user = result.user;
 * // This gives you a Twitter Access Token and Secret.
 * const credential = TwitterAuthProvider.credentialFromResult(result);
 * const token = credential.accessToken;
 * const secret = credential.secret;
 * ```
 *
 * @public
 */ class aU extends aN{constructor(){super("twitter.com")}static credential(a,b){return aD._fromParams({providerId:aU.PROVIDER_ID,signInMethod:aU.TWITTER_SIGN_IN_METHOD,oauthToken:a,oauthTokenSecret:b})}static credentialFromResult(a){return aU.credentialFromTaggedObject(a)}static credentialFromError(a){return aU.credentialFromTaggedObject(a.customData||{})}static credentialFromTaggedObject({_tokenResponse:a}){if(!a)return null;let{oauthAccessToken:b,oauthTokenSecret:c}=a;if(!b||!c)return null;try{return aU.credential(b,c)}catch(d){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function aV(a,b){return I(a,"POST","/v1/accounts:signUp",F(a,b))}aU.TWITTER_SIGN_IN_METHOD="twitter.com",aU.PROVIDER_ID="twitter.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class aW{constructor(a){this.user=a.user,this.providerId=a.providerId,this._tokenResponse=a._tokenResponse,this.operationType=a.operationType}static async _fromIdTokenResponse(a,b,c,d=!1){let e=await aa._fromIdTokenResponse(a,c,d),f=aX(c),g=new aW({user:e,providerId:f,_tokenResponse:c,operationType:b});return g}static async _forOperation(a,b,c){await a._updateTokensIfNecessary(c,!0);let d=aX(c);return new aW({user:a,providerId:d,_tokenResponse:c,operationType:b})}}function aX(a){return a.providerId?a.providerId:"phoneNumber"in a?"phone":null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class aY extends e.ZR{constructor(a,b,c,d){var e;super(b.code,b.message),this.operationType=c,this.user=d,Object.setPrototypeOf(this,aY.prototype),this.customData={appName:a.name,tenantId:null!==(e=a.tenantId)&& void 0!==e?e:void 0,_serverResponse:b.customData._serverResponse,operationType:c}}static _fromErrorAndOperation(a,b,c,d){return new aY(a,b,c,d)}}function aZ(a,b,c,d){let e="reauthenticate"===b?c._getReauthenticationResolver(a):c._getIdTokenResponse(a);return e.catch(c=>{if("auth/multi-factor-auth-required"===c.code)throw aY._fromErrorAndOperation(a,c,b,d);throw c})}async function a$(a,b,c=!1){let d=await S(a,b._linkToIdToken(a.auth,await a.getIdToken()),c);return aW._forOperation(a,"link",d)}async function a_(a,b,c){var d;await V(b);let e=(d=b.providerData,new Set(d.map(({providerId:a})=>a).filter(a=>!!a)));t(e.has(c)===a,b.auth,!1===a?"provider-already-linked":"no-such-provider")}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function a0(a,b,c=!1){var d;let{auth:e}=a,f="reauthenticate";try{let g=await S(a,aZ(e,f,b,a),c);t(g.idToken,e,"internal-error");let h=R(g.idToken);t(h,e,"internal-error");let{sub:i}=h;return t(a.uid===i,e,"user-mismatch"),aW._forOperation(a,f,g)}catch(j){throw(null===(d=j)|| void 0===d?void 0:d.code)==="auth/user-not-found"&&o(e,"user-mismatch"),j}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function a1(a,b,c=!1){let d="signIn",e=await aZ(a,d,b),f=await aW._fromIdTokenResponse(a,d,e);return c||await a._updateCurrentUser(f.user),f}async function a2(a,b){return a1(ar(a),b)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function a3(a,b){return I(a,"POST","/v1/accounts:signInWithCustomToken",F(a,b))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Asynchronously signs in using a custom token.
 *
 * @remarks
 * Custom tokens are used to integrate Firebase Auth with existing auth systems, and must
 * be generated by an auth backend using the
 * {@link https://firebase.google.com/docs/reference/admin/node/admin.auth.Auth#createcustomtoken | createCustomToken}
 * method in the {@link https://firebase.google.com/docs/auth/admin | Admin SDK} .
 *
 * Fails with an error if the token is invalid, expired, or not accepted by the Firebase Auth service.
 *
 * @param auth - The {@link Auth} instance.
 * @param customToken - The custom token to sign in with.
 *
 * @public
 */ async function a4(a,b){let c=ar(a),d=await a3(c,{token:b,returnSecureToken:!0}),e=await aW._fromIdTokenResponse(c,"signIn",d);return await c._updateCurrentUser(e.user),e}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class a5{constructor(a,b){this.factorId=a,this.uid=b.mfaEnrollmentId,this.enrollmentTime=new Date(b.enrolledAt).toUTCString(),this.displayName=b.displayName}static _fromServerResponse(a,b){return"phoneInfo"in b?a6._fromServerResponse(a,b):o(a,"internal-error")}}class a6 extends null{constructor(a){super("phone",a),this.phoneNumber=a.phoneInfo}static _fromServerResponse(a,b){return new a6(b)}}async function a7(a,b,c){let d=ar(a),e=await aV(d,{returnSecureToken:!0,email:b,password:c}),f=await aW._fromIdTokenResponse(d,"signIn",e);return await d._updateCurrentUser(f.user),f}function a8(a,b,c){return a2((0,e.m9)(a),aL.credential(b,c))}class a9{constructor(a,b){this.type=a,this.credential=b}static _fromIdtoken(a){return new a9("enroll",a)}static _fromMfaPendingCredential(a){return new a9("signin",a)}toJSON(){let a="enroll"===this.type?"idToken":"pendingCredential";return{multiFactorSession:{[a]:this.credential}}}static fromJSON(a){var b,c;if(null==a?void 0:a.multiFactorSession){if(null===(b=a.multiFactorSession)|| void 0===b?void 0:b.pendingCredential)return a9._fromMfaPendingCredential(a.multiFactorSession.pendingCredential);if(null===(c=a.multiFactorSession)|| void 0===c?void 0:c.idToken)return a9._fromIdtoken(a.multiFactorSession.idToken)}return null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class ba{constructor(a,b,c){this.session=a,this.hints=b,this.signInResolver=c}static _fromError(a,b){let c=ar(a),d=b.customData._serverResponse,e=(d.mfaInfo||[]).map(a=>a5._fromServerResponse(c,a));t(d.mfaPendingCredential,c,"internal-error");let f=a9._fromMfaPendingCredential(d.mfaPendingCredential);return new ba(f,e,async a=>{let e=await a._process(c,f);delete d.mfaInfo,delete d.mfaPendingCredential;let g=Object.assign(Object.assign({},d),{idToken:e.idToken,refreshToken:e.refreshToken});switch(b.operationType){case"signIn":let h=await aW._fromIdTokenResponse(c,b.operationType,g);return await c._updateCurrentUser(h.user),h;case"reauthenticate":return t(b.user,c,"internal-error"),aW._forOperation(b.user,b.operationType,g);default:o(c,"internal-error")}})}async resolveSignIn(a){return this.signInResolver(a)}}class bb{constructor(a){this.user=a,this.enrolledFactors=[],a._onReload(b=>{b.mfaInfo&&(this.enrolledFactors=b.mfaInfo.map(b=>a5._fromServerResponse(a.auth,b)))})}static _fromUser(a){return new bb(a)}async getSession(){return a9._fromIdtoken(await this.user.getIdToken())}async enroll(a,b){let c=await this.getSession(),d=await S(this.user,a._process(this.user.auth,c,b));return await this.user._updateTokensIfNecessary(d),this.user.reload()}async unenroll(a){var b,c,d;let e="string"==typeof a?a:a.uid,f=await this.user.getIdToken(),g=await S(this.user,(c=this.user.auth,G(c,"POST","/v2/accounts/mfaEnrollment:withdraw",F(c,d={idToken:f,mfaEnrollmentId:e}))));this.enrolledFactors=this.enrolledFactors.filter(({uid:a})=>a!==e),await this.user._updateTokensIfNecessary(g);try{await this.user.reload()}catch(h){if((null===(b=h)|| void 0===b?void 0:b.code)!=="auth/user-token-expired")throw h}}}new WeakMap;let bc="__sak";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ // There are two different browser persistence types: local and session.
// Both have the same implementation but use a different underlying storage
// object.
class bd{constructor(a,b){this.storageRetriever=a,this.type=b}_isAvailable(){try{if(!this.storage)return Promise.resolve(!1);return this.storage.setItem(bc,"1"),this.storage.removeItem(bc),Promise.resolve(!0)}catch(a){return Promise.resolve(!1)}}_set(a,b){return this.storage.setItem(a,JSON.stringify(b)),Promise.resolve()}_get(a){let b=this.storage.getItem(a);return Promise.resolve(b?JSON.parse(b):null)}_remove(a){return this.storage.removeItem(a),Promise.resolve()}get storage(){return this.storageRetriever()}}class be extends bd{constructor(){super(()=>window.localStorage,"LOCAL"),this.boundEventHandler=(a,b)=>this.onStorageEvent(a,b),this.listeners={},this.localCache={},this.pollTimer=null,this.safariLocalStorageNotSynced=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function(){let a=(0,e.z$)();return ah(a)||an(a)}()&&function(){try{return!!(window&&window!==window.top)}catch(a){return!1}}(),this.fallbackToPolling=ao(),this._shouldAllowMigration=!0}forAllChangedKeys(a){for(let b of Object.keys(this.listeners)){let c=this.storage.getItem(b),d=this.localCache[b];c!==d&&a(b,d,c)}}onStorageEvent(a,b=!1){if(!a.key){this.forAllChangedKeys((a,b,c)=>{this.notifyListeners(a,c)});return}let c=a.key;if(b?this.detachListener():this.stopPolling(),this.safariLocalStorageNotSynced){let d=this.storage.getItem(c);if(a.newValue!==d)null!==a.newValue?this.storage.setItem(c,a.newValue):this.storage.removeItem(c);else if(this.localCache[c]===a.newValue&&!b)return}let f=()=>{let a=this.storage.getItem(c);(b||this.localCache[c]!==a)&&this.notifyListeners(c,a)},g=this.storage.getItem(c);(0,e.w1)()&&10===document.documentMode&&g!==a.newValue&&a.newValue!==a.oldValue?setTimeout(f,10):f()}notifyListeners(a,b){this.localCache[a]=b;let c=this.listeners[a];if(c)for(let d of Array.from(c))d(b?JSON.parse(b):b)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(()=>{this.forAllChangedKeys((a,b,c)=>{this.onStorageEvent(new StorageEvent("storage",{key:a,oldValue:b,newValue:c}),!0)})},1e3)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}attachListener(){window.addEventListener("storage",this.boundEventHandler)}detachListener(){window.removeEventListener("storage",this.boundEventHandler)}_addListener(a,b){0===Object.keys(this.listeners).length&&(this.fallbackToPolling?this.startPolling():this.attachListener()),this.listeners[a]||(this.listeners[a]=new Set,this.localCache[a]=this.storage.getItem(a)),this.listeners[a].add(b)}_removeListener(a,b){this.listeners[a]&&(this.listeners[a].delete(b),0===this.listeners[a].size&&delete this.listeners[a]),0===Object.keys(this.listeners).length&&(this.detachListener(),this.stopPolling())}async _set(a,b){await super._set(a,b),this.localCache[a]=JSON.stringify(b)}async _get(a){let b=await super._get(a);return this.localCache[a]=JSON.stringify(b),b}async _remove(a){await super._remove(a),delete this.localCache[a]}}be.type="LOCAL";let bf=be;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class bg extends bd{constructor(){super(()=>window.sessionStorage,"SESSION")}_addListener(a,b){}_removeListener(a,b){}}bg.type="SESSION";let bh=bg;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Interface class for receiving messages.
 *
 */ class bi{constructor(a){this.eventTarget=a,this.handlersMap={},this.boundEventHandler=this.handleEvent.bind(this)}static _getInstance(a){let b=this.receivers.find(b=>b.isListeningto(a));if(b)return b;let c=new bi(a);return this.receivers.push(c),c}isListeningto(a){return this.eventTarget===a}async handleEvent(a){var b;let c=a,{eventId:d,eventType:e,data:f}=c.data,g=this.handlersMap[e];if(!(null==g?void 0:g.size))return;c.ports[0].postMessage({status:"ack",eventId:d,eventType:e});let h=Array.from(g).map(async a=>a(c.origin,f)),i=await Promise.all((b=h).map(async a=>{try{let b=await a;return{fulfilled:!0,value:b}}catch(c){return{fulfilled:!1,reason:c}}}));c.ports[0].postMessage({status:"done",eventId:d,eventType:e,response:i})}_subscribe(a,b){0===Object.keys(this.handlersMap).length&&this.eventTarget.addEventListener("message",this.boundEventHandler),this.handlersMap[a]||(this.handlersMap[a]=new Set),this.handlersMap[a].add(b)}_unsubscribe(a,b){this.handlersMap[a]&&b&&this.handlersMap[a].delete(b),b&&0!==this.handlersMap[a].size||delete this.handlersMap[a],0===Object.keys(this.handlersMap).length&&this.eventTarget.removeEventListener("message",this.boundEventHandler)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function bj(a="",b=10){let c="";for(let d=0;d<b;d++)c+=Math.floor(10*Math.random());return a+c}bi.receivers=[];/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Interface for sending messages and waiting for a completion response.
 *
 */ class bk{constructor(a){this.target=a,this.handlers=new Set}removeMessageHandler(a){a.messageChannel&&(a.messageChannel.port1.removeEventListener("message",a.onMessage),a.messageChannel.port1.close()),this.handlers.delete(a)}async _send(a,b,c=50){let d="undefined"!=typeof MessageChannel?new MessageChannel:null;if(!d)throw Error("connection_unavailable");let e,f;return new Promise((g,h)=>{let i=bj("",20);d.port1.start();let j=setTimeout(()=>{h(Error("unsupported_event"))},c);f={messageChannel:d,onMessage(a){let b=a;if(b.data.eventId===i)switch(b.data.status){case"ack":clearTimeout(j),e=setTimeout(()=>{h(Error("timeout"))},3e3);break;case"done":clearTimeout(e),g(b.data.response);break;default:clearTimeout(j),clearTimeout(e),h(Error("invalid_response"))}}},this.handlers.add(f),d.port1.addEventListener("message",f.onMessage),this.target.postMessage({eventType:a,eventId:i,data:b},[d.port2])}).finally(()=>{f&&this.removeMessageHandler(f)})}}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function bl(){return void 0!==window.WorkerGlobalScope&&"function"==typeof window.importScripts}async function bm(){if(!(null==navigator?void 0:navigator.serviceWorker))return null;try{let a=await navigator.serviceWorker.ready;return a.active}catch(b){return null}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ let bn="firebaseLocalStorageDb",bo="firebaseLocalStorage",bp="fbase_key";class bq{constructor(a){this.request=a}toPromise(){return new Promise((a,b)=>{this.request.addEventListener("success",()=>{a(this.request.result)}),this.request.addEventListener("error",()=>{b(this.request.error)})})}}function br(a,b){return a.transaction([bo],b?"readwrite":"readonly").objectStore(bo)}function bs(){let a=indexedDB.open(bn,1);return new Promise((b,c)=>{a.addEventListener("error",()=>{c(a.error)}),a.addEventListener("upgradeneeded",()=>{let b=a.result;try{b.createObjectStore(bo,{keyPath:bp})}catch(d){c(d)}}),a.addEventListener("success",async()=>{let c=a.result;c.objectStoreNames.contains(bo)?b(c):(c.close(),await function(){let a=indexedDB.deleteDatabase(bn);return new bq(a).toPromise()}(),b(await bs()))})})}async function bt(a,b,c){let d=br(a,!0).put({[bp]:b,value:c});return new bq(d).toPromise()}async function bu(a,b){let c=br(a,!1).get(b),d=await new bq(c).toPromise();return void 0===d?null:d.value}function bv(a,b){let c=br(a,!0).delete(b);return new bq(c).toPromise()}class bw{constructor(){this.type="LOCAL",this._shouldAllowMigration=!0,this.listeners={},this.localCache={},this.pollTimer=null,this.pendingWrites=0,this.receiver=null,this.sender=null,this.serviceWorkerReceiverAvailable=!1,this.activeServiceWorker=null,this._workerInitializationPromise=this.initializeServiceWorkerMessaging().then(()=>{},()=>{})}async _openDb(){return this.db||(this.db=await bs()),this.db}async _withRetries(a){let b=0;for(;;)try{let c=await this._openDb();return await a(c)}catch(d){if(b++ >3)throw d;this.db&&(this.db.close(),this.db=void 0)}}async initializeServiceWorkerMessaging(){return bl()?this.initializeReceiver():this.initializeSender()}async initializeReceiver(){this.receiver=bi._getInstance(bl()?self:null),this.receiver._subscribe("keyChanged",async(a,b)=>{let c=await this._poll();return{keyProcessed:c.includes(b.key)}}),this.receiver._subscribe("ping",async(a,b)=>["keyChanged"])}async initializeSender(){var a,b;if(this.activeServiceWorker=await bm(),!this.activeServiceWorker)return;this.sender=new bk(this.activeServiceWorker);let c=await this.sender._send("ping",{},800);c&&(null===(a=c[0])|| void 0===a?void 0:a.fulfilled)&&(null===(b=c[0])|| void 0===b?void 0:b.value.includes("keyChanged"))&&(this.serviceWorkerReceiverAvailable=!0)}async notifyServiceWorker(a){var b;if(this.sender&&this.activeServiceWorker&&((null===(b=null==navigator?void 0:navigator.serviceWorker)|| void 0===b?void 0:b.controller)||null)===this.activeServiceWorker)try{await this.sender._send("keyChanged",{key:a},this.serviceWorkerReceiverAvailable?800:50)}catch(c){}}async _isAvailable(){try{if(!indexedDB)return!1;let a=await bs();return await bt(a,bc,"1"),await bv(a,bc),!0}catch(b){}return!1}async _withPendingWrite(a){this.pendingWrites++;try{await a()}finally{this.pendingWrites--}}async _set(a,b){return this._withPendingWrite(async()=>(await this._withRetries(c=>bt(c,a,b)),this.localCache[a]=b,this.notifyServiceWorker(a)))}async _get(a){let b=await this._withRetries(b=>bu(b,a));return this.localCache[a]=b,b}async _remove(a){return this._withPendingWrite(async()=>(await this._withRetries(b=>bv(b,a)),delete this.localCache[a],this.notifyServiceWorker(a)))}async _poll(){let a=await this._withRetries(a=>{let b=br(a,!1).getAll();return new bq(b).toPromise()});if(!a||0!==this.pendingWrites)return[];let b=[],c=new Set;for(let{fbase_key:d,value:e}of a)c.add(d),JSON.stringify(this.localCache[d])!==JSON.stringify(e)&&(this.notifyListeners(d,e),b.push(d));for(let f of Object.keys(this.localCache))this.localCache[f]&&!c.has(f)&&(this.notifyListeners(f,null),b.push(f));return b}notifyListeners(a,b){this.localCache[a]=b;let c=this.listeners[a];if(c)for(let d of Array.from(c))d(b)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(async()=>this._poll(),800)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}_addListener(a,b){0===Object.keys(this.listeners).length&&this.startPolling(),this.listeners[a]||(this.listeners[a]=new Set,this._get(a)),this.listeners[a].add(b)}_removeListener(a,b){this.listeners[a]&&(this.listeners[a].delete(b),0===this.listeners[a].size&&delete this.listeners[a]),0===Object.keys(this.listeners).length&&this.stopPolling()}}bw.type="LOCAL";let bx=bw;function by(a){return`__${a}${Math.floor(1e6*Math.random())}`}class bz{constructor(a,b,c){this.params=c,this.timerId=null,this.deleted=!1,this.responseToken=null,this.clickHandler=()=>{this.execute()};let d="string"==typeof a?document.getElementById(a):a;t(d,"argument-error",{appName:b}),this.container=d,this.isVisible="invisible"!==this.params.size,this.isVisible?this.execute():this.container.addEventListener("click",this.clickHandler)}getResponse(){return this.checkIfDeleted(),this.responseToken}delete(){this.checkIfDeleted(),this.deleted=!0,this.timerId&&(clearTimeout(this.timerId),this.timerId=null),this.container.removeEventListener("click",this.clickHandler)}execute(){this.checkIfDeleted(),!this.timerId&&(this.timerId=window.setTimeout(()=>{this.responseToken=bA(50);let{callback:a,"expired-callback":b}=this.params;if(a)try{a(this.responseToken)}catch(c){}this.timerId=window.setTimeout(()=>{if(this.timerId=null,this.responseToken=null,b)try{b()}catch(a){}this.isVisible&&this.execute()},6e4)},500))}checkIfDeleted(){if(this.deleted)throw Error("reCAPTCHA mock was already deleted!")}}function bA(a){let b=[],c="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";for(let d=0;d<a;d++)b.push(c.charAt(Math.floor(Math.random()*c.length)));return b.join("")}by("rcb"),new A(3e4,6e4);async function bB(a,b,c){var d,e,f,g,h;let i=await c.verify();try{t("string"==typeof i,a,"argument-error"),t("recaptcha"===c.type,a,"argument-error");let j;if(j="string"==typeof b?{phoneNumber:b}:b,"session"in j){let k=j.session;if("phoneNumber"in j){t("enroll"===k.type,a,"internal-error");let l=await (e=a,f={idToken:k.credential,phoneEnrollmentInfo:{phoneNumber:j.phoneNumber,recaptchaToken:i}},G(e,"POST","/v2/accounts/mfaEnrollment:start",F(e,f)));return l.phoneSessionInfo.sessionInfo}{t("signin"===k.type,a,"internal-error");let m=(null===(d=j.multiFactorHint)|| void 0===d?void 0:d.uid)||j.multiFactorUid;t(m,a,"missing-multi-factor-info");let n=await (g=a,h={mfaPendingCredential:k.credential,mfaEnrollmentId:m,phoneSignInInfo:{recaptchaToken:i}},G(g,"POST","/v2/accounts/mfaSignIn:start",F(g,h)));return n.phoneResponseInfo.sessionInfo}}{let{sessionInfo:o}=await aE(a,{phoneNumber:j.phoneNumber,recaptchaToken:i});return o}}finally{c._reset()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Provider for generating an {@link PhoneAuthCredential}.
 *
 * @example
 * ```javascript
 * // 'recaptcha-container' is the ID of an element in the DOM.
 * const applicationVerifier = new RecaptchaVerifier('recaptcha-container');
 * const provider = new PhoneAuthProvider(auth);
 * const verificationId = await provider.verifyPhoneNumber('+16505550101', applicationVerifier);
 * // Obtain the verificationCode from the user.
 * const phoneCredential = PhoneAuthProvider.credential(verificationId, verificationCode);
 * const userCredential = await signInWithCredential(auth, phoneCredential);
 * ```
 *
 * @public
 */ class bC{constructor(a){this.providerId=bC.PROVIDER_ID,this.auth=ar(a)}verifyPhoneNumber(a,b){return bB(this.auth,a,(0,e.m9)(b))}static credential(a,b){return aJ._fromVerification(a,b)}static credentialFromResult(a){return bC.credentialFromTaggedObject(a)}static credentialFromError(a){return bC.credentialFromTaggedObject(a.customData||{})}static credentialFromTaggedObject({_tokenResponse:a}){if(!a)return null;let{phoneNumber:b,temporaryProof:c}=a;return b&&c?aJ._fromTokenResponse(b,c):null}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Chooses a popup/redirect resolver to use. This prefers the override (which
 * is directly passed in), and falls back to the property set on the auth
 * object. If neither are available, this function errors w/ an argument error.
 */ function bD(a,b){return b?x(b):(t(a._popupRedirectResolver,a,"argument-error"),a._popupRedirectResolver)}bC.PROVIDER_ID="phone",bC.PHONE_SIGN_IN_METHOD="phone";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class bE extends au{constructor(a){super("custom","custom"),this.params=a}_getIdTokenResponse(a){return aC(a,this._buildIdpRequest())}_linkToIdToken(a,b){return aC(a,this._buildIdpRequest(b))}_getReauthenticationResolver(a){return aC(a,this._buildIdpRequest())}_buildIdpRequest(a){let b={requestUri:this.params.requestUri,sessionId:this.params.sessionId,postBody:this.params.postBody,tenantId:this.params.tenantId,pendingToken:this.params.pendingToken,returnSecureToken:!0,returnIdpCredential:!0};return a&&(b.idToken=a),b}}function bF(a){return a1(a.auth,new bE(a),a.bypassAuthState)}function bG(a){let{auth:b,user:c}=a;return t(c,b,"internal-error"),a0(c,new bE(a),a.bypassAuthState)}async function bH(a){let{auth:b,user:c}=a;return t(c,b,"internal-error"),a$(c,new bE(a),a.bypassAuthState)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Popup event manager. Handles the popup's entire lifecycle; listens to auth
 * events
 */ class bI{constructor(a,b,c,d,e=!1){this.auth=a,this.resolver=c,this.user=d,this.bypassAuthState=e,this.pendingPromise=null,this.eventManager=null,this.filter=Array.isArray(b)?b:[b]}execute(){return new Promise(async(a,b)=>{this.pendingPromise={resolve:a,reject:b};try{this.eventManager=await this.resolver._initialize(this.auth),await this.onExecution(),this.eventManager.registerConsumer(this)}catch(c){this.reject(c)}})}async onAuthEvent(a){let{urlResponse:b,sessionId:c,postBody:d,tenantId:e,error:f,type:g}=a;if(f){this.reject(f);return}let h={auth:this.auth,requestUri:b,sessionId:c,tenantId:e||void 0,postBody:d||void 0,user:this.user,bypassAuthState:this.bypassAuthState};try{this.resolve(await this.getIdpTask(g)(h))}catch(i){this.reject(i)}}onError(a){this.reject(a)}getIdpTask(a){switch(a){case"signInViaPopup":case"signInViaRedirect":return bF;case"linkViaPopup":case"linkViaRedirect":return bH;case"reauthViaPopup":case"reauthViaRedirect":return bG;default:o(this.auth,"internal-error")}}resolve(a){v(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.resolve(a),this.unregisterAndCleanUp()}reject(a){v(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.reject(a),this.unregisterAndCleanUp()}unregisterAndCleanUp(){this.eventManager&&this.eventManager.unregisterConsumer(this),this.pendingPromise=null,this.cleanUp()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ let bJ=new A(2e3,1e4);class bK extends bI{constructor(a,b,c,d,e){super(a,b,d,e),this.provider=c,this.authWindow=null,this.pollId=null,bK.currentPopupAction&&bK.currentPopupAction.cancel(),bK.currentPopupAction=this}async executeNotNull(){let a=await this.execute();return t(a,this.auth,"internal-error"),a}async onExecution(){v(1===this.filter.length,"Popup operations only handle one event");let a=bj();this.authWindow=await this.resolver._openPopup(this.auth,this.provider,this.filter[0],a),this.authWindow.associatedEvent=a,this.resolver._originValidation(this.auth).catch(a=>{this.reject(a)}),this.resolver._isIframeWebStorageSupported(this.auth,a=>{a||this.reject(p(this.auth,"web-storage-unsupported"))}),this.pollUserCancellation()}get eventId(){var a;return(null===(a=this.authWindow)|| void 0===a?void 0:a.associatedEvent)||null}cancel(){this.reject(p(this.auth,"cancelled-popup-request"))}cleanUp(){this.authWindow&&this.authWindow.close(),this.pollId&&window.clearTimeout(this.pollId),this.authWindow=null,this.pollId=null,bK.currentPopupAction=null}pollUserCancellation(){let a=()=>{var b,c;if(null===(c=null===(b=this.authWindow)|| void 0===b?void 0:b.window)|| void 0===c?void 0:c.closed){this.pollId=window.setTimeout(()=>{this.pollId=null,this.reject(p(this.auth,"popup-closed-by-user"))},2e3);return}this.pollId=window.setTimeout(a,bJ.get())};a()}}bK.currentPopupAction=null;let bL=new Map;class bM extends bI{constructor(a,b,c=!1){super(a,["signInViaRedirect","linkViaRedirect","reauthViaRedirect","unknown"],b,void 0,c),this.eventId=null}async execute(){let a=bL.get(this.auth._key());if(!a){try{let b=await bN(this.resolver,this.auth),c=b?await super.execute():null;a=()=>Promise.resolve(c)}catch(d){a=()=>Promise.reject(d)}bL.set(this.auth._key(),a)}return this.bypassAuthState||bL.set(this.auth._key(),()=>Promise.resolve(null)),a()}async onAuthEvent(a){if("signInViaRedirect"===a.type)return super.onAuthEvent(a);if("unknown"===a.type){this.resolve(null);return}if(a.eventId){let b=await this.auth._redirectUserForId(a.eventId);if(b)return this.user=b,super.onAuthEvent(a);this.resolve(null)}}async onExecution(){}cleanUp(){}}async function bN(a,b){let c=bQ(b),d=bP(a);if(!await d._isAvailable())return!1;let e=await d._get(c)==="true";return await d._remove(c),e}async function bO(a,b){return bP(a)._set(bQ(b),"true")}function bP(a){return x(a._redirectPersistence)}function bQ(a){return ad("pendingRedirect",a.config.apiKey,a.name)}async function bR(a,b,c=!1){let d=ar(a),e=bD(d,b),f=new bM(d,e,c),g=await f.execute();return g&&!c&&(delete g.user._redirectEventId,await d._persistUserIfCurrent(g.user),await d._setRedirectUser(null,b)),g}async function bS(a){let b=bj(`${a.uid}:::`);return a._redirectEventId=b,await a.auth._setRedirectUser(a),await a.auth._persistUserIfCurrent(a),b}class bT{constructor(a){this.auth=a,this.cachedEventUids=new Set,this.consumers=new Set,this.queuedRedirectEvent=null,this.hasHandledPotentialRedirect=!1,this.lastProcessedEventTime=Date.now()}registerConsumer(a){this.consumers.add(a),this.queuedRedirectEvent&&this.isEventForConsumer(this.queuedRedirectEvent,a)&&(this.sendToConsumer(this.queuedRedirectEvent,a),this.saveEventToCache(this.queuedRedirectEvent),this.queuedRedirectEvent=null)}unregisterConsumer(a){this.consumers.delete(a)}onEvent(a){if(this.hasEventBeenHandled(a))return!1;let b=!1;return this.consumers.forEach(c=>{this.isEventForConsumer(a,c)&&(b=!0,this.sendToConsumer(a,c),this.saveEventToCache(a))}),this.hasHandledPotentialRedirect||!bW(a)||(this.hasHandledPotentialRedirect=!0,b||(this.queuedRedirectEvent=a,b=!0)),b}sendToConsumer(a,b){var c;if(a.error&&!bV(a)){let d=(null===(c=a.error.code)|| void 0===c?void 0:c.split("auth/")[1])||"internal-error";b.onError(p(this.auth,d))}else b.onAuthEvent(a)}isEventForConsumer(a,b){let c=null===b.eventId|| !!a.eventId&&a.eventId===b.eventId;return b.filter.includes(a.type)&&c}hasEventBeenHandled(a){return Date.now()-this.lastProcessedEventTime>=6e5&&this.cachedEventUids.clear(),this.cachedEventUids.has(bU(a))}saveEventToCache(a){this.cachedEventUids.add(bU(a)),this.lastProcessedEventTime=Date.now()}}function bU(a){return[a.type,a.eventId,a.sessionId,a.tenantId].filter(a=>a).join("-")}function bV({type:a,error:b}){return"unknown"===a&&(null==b?void 0:b.code)==="auth/no-auth-event"}function bW(a){switch(a.type){case"signInViaRedirect":case"linkViaRedirect":case"reauthViaRedirect":return!0;case"unknown":return bV(a);default:return!1}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ async function bX(a,b={}){return G(a,"GET","/v1/projects",b)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ let bY=/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,bZ=/^https?/;async function b$(a){if(a.config.emulator)return;let{authorizedDomains:b}=await bX(a);for(let c of b)try{if(b_(c))return}catch(d){}o(a,"unauthorized-domain")}function b_(a){let b=y(),{protocol:c,hostname:d}=new URL(b);if(a.startsWith("chrome-extension://")){let e=new URL(a);return""===e.hostname&&""===d?"chrome-extension:"===c&&a.replace("chrome-extension://","")===b.replace("chrome-extension://",""):"chrome-extension:"===c&&e.hostname===d}if(!bZ.test(c))return!1;if(bY.test(a))return d===a;let f=a.replace(/\./g,"\\."),g=RegExp("^(.+\\."+f+"|"+f+")$","i");return g.test(d)}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ let b0=new A(3e4,6e4);function b1(){let a=window.___jsl;if(null==a?void 0:a.H){for(let b of Object.keys(a.H))if(a.H[b].r=a.H[b].r||[],a.H[b].L=a.H[b].L||[],a.H[b].r=[...a.H[b].L],a.CP)for(let c=0;c<a.CP.length;c++)a.CP[c]=null}}let b2=null,b3=new A(5e3,15e3),b4={style:{position:"absolute",top:"-100px",width:"1px",height:"1px"},"aria-hidden":"true",tabindex:"-1"},b5=new Map([["identitytoolkit.googleapis.com","p"],["staging-identitytoolkit.sandbox.googleapis.com","s"],["test-identitytoolkit.sandbox.googleapis.com","t"]]);async function b6(a){var b,c;let d=await (b=a,b2=b2||(c=b,new Promise((a,b)=>{var d,e,f,g;function h(){b1(),gapi.load("gapi.iframes",{callback(){a(gapi.iframes.getContext())},ontimeout(){b1(),b(p(c,"network-request-failed"))},timeout:b0.get()})}if(null===(e=null===(d=window.gapi)|| void 0===d?void 0:d.iframes)|| void 0===e?void 0:e.Iframe)a(gapi.iframes.getContext());else if(null===(f=window.gapi)|| void 0===f?void 0:f.load)h();else{let i=by("iframefcb");return window[i]=()=>{gapi.load?h():b(p(c,"network-request-failed"))},(g=`https://apis.google.com/js/api.js?onload=${i}`,new Promise((a,b)=>{var c,d;let e=document.createElement("script");e.setAttribute("src",g),e.onload=a,e.onerror=a=>{let c=p("internal-error");c.customData=a,b(c)},e.type="text/javascript",e.charset="UTF-8",(null!==(d=null===(c=document.getElementsByTagName("head"))|| void 0===c?void 0:c[0])&& void 0!==d?d:document).appendChild(e)})).catch(a=>b(a))}}).catch(a=>{throw b2=null,a}))),g=window.gapi;return t(g,a,"internal-error"),d.open({where:document.body,url:function(a){let b=a.config;t(b.authDomain,a,"auth-domain-config-required");let c=b.emulator?B(b,"emulator/auth/iframe"):`https://${a.config.authDomain}/__/auth/iframe`,d={apiKey:b.apiKey,appName:a.name,v:f.Jn},g=b5.get(a.config.apiHost);g&&(d.eid=g);let h=a._getFrameworks();return h.length&&(d.fw=h.join(",")),`${c}?${(0,e.xO)(d).slice(1)}`}(a),messageHandlersFilter:g.iframes.CROSS_ORIGIN_IFRAMES_FILTER,attributes:b4,dontclear:!0},b=>new Promise(async(c,d)=>{await b.restyle({setHideOnLeave:!1});let e=p(a,"network-request-failed"),f=window.setTimeout(()=>{d(e)},b3.get());function g(){window.clearTimeout(f),c(b)}b.ping(g).then(g,()=>{d(e)})}))}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ let b7={location:"yes",resizable:"yes",statusbar:"yes",toolbar:"no"};class b8{constructor(a){this.window=a,this.associatedEvent=null}close(){if(this.window)try{this.window.close()}catch(a){}}}function b9(a,b,c,d,g,h){t(a.config.authDomain,a,"auth-domain-config-required"),t(a.config.apiKey,a,"invalid-api-key");let i={apiKey:a.config.apiKey,appName:a.name,authType:c,redirectUrl:d,v:f.Jn,eventId:g};if(b instanceof aM)for(let[j,k]of(b.setDefaultLanguage(a.languageCode),i.providerId=b.providerId||"",(0,e.xb)(b.getCustomParameters())||(i.customParameters=JSON.stringify(b.getCustomParameters())),Object.entries(h||{})))i[j]=k;if(b instanceof aN){let l=b.getScopes().filter(a=>""!==a);l.length>0&&(i.scopes=l.join(","))}a.tenantId&&(i.tid=a.tenantId);let m=i;for(let n of Object.keys(m))void 0===m[n]&&delete m[n];return`${ca(a)}?${(0,e.xO)(m).slice(1)}`}function ca({config:a}){return a.emulator?B(a,"emulator/auth/handler"):`https://${a.authDomain}/__/auth/handler`}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * The special web storage event
 *
 */ let cb="webStorageSupport",cc=class{constructor(){this.eventManagers={},this.iframes={},this.originValidationPromises={},this._redirectPersistence=bh,this._completeRedirectFn=bR,this._overrideRedirectResult=function(a,b){bL.set(a._key(),b)}}async _openPopup(a,b,c,d){var f;v(null===(f=this.eventManagers[a._key()])|| void 0===f?void 0:f.manager,"_initialize() not called before _openPopup()");let g=b9(a,b,c,y(),d);return function(a,b,c,d=500,f=600){let g=Math.max((window.screen.availHeight-f)/2,0).toString(),h=Math.max((window.screen.availWidth-d)/2,0).toString(),i="",j=Object.assign(Object.assign({},b7),{width:d.toString(),height:f.toString(),top:g,left:h}),k=(0,e.z$)().toLowerCase();c&&(i=ai(k)?"_blank":c),ag(k)&&(b=b||"http://localhost",j.scrollbars="yes");let l=Object.entries(j).reduce((a,[b,c])=>`${a}${b}=${c},`,"");if(function(a=(0,e.z$)()){var b;return an(a)&&!!(null===(b=window.navigator)|| void 0===b?void 0:b.standalone)}(k)&&"_self"!==i)return function a(b,c){let d=document.createElement("a");d.href=b,d.target=c;let e=document.createEvent("MouseEvent");e.initMouseEvent("click",!0,!0,window,1,0,0,0,0,!1,!1,!1,!1,1,null),d.dispatchEvent(e)}(b||"",i),new b8(null);let m=window.open(b||"",i,l);t(m,a,"popup-blocked");try{m.focus()}catch(n){}return new b8(m)}(a,g,bj())}async _openRedirect(a,b,c,d){var e;return await this._originValidation(a),e=b9(a,b,c,y(),d),window.location.href=e,new Promise(()=>{})}_initialize(a){let b=a._key();if(this.eventManagers[b]){let{manager:c,promise:d}=this.eventManagers[b];return c?Promise.resolve(c):(v(d,"If manager is not set, promise should be"),d)}let e=this.initAndGetManager(a);return this.eventManagers[b]={promise:e},e.catch(()=>{delete this.eventManagers[b]}),e}async initAndGetManager(a){let b=await b6(a),c=new bT(a);return b.register("authEvent",b=>{t(null==b?void 0:b.authEvent,a,"invalid-auth-event");let d=c.onEvent(b.authEvent);return{status:d?"ACK":"ERROR"}},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER),this.eventManagers[a._key()]={manager:c},this.iframes[a._key()]=b,c}_isIframeWebStorageSupported(a,b){let c=this.iframes[a._key()];c.send(cb,{type:cb},c=>{var d;let e=null===(d=null==c?void 0:c[0])|| void 0===d?void 0:d[cb];void 0!==e&&b(!!e),o(a,"internal-error")},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER)}_originValidation(a){let b=a._key();return this.originValidationPromises[b]||(this.originValidationPromises[b]=b$(a)),this.originValidationPromises[b]}get _shouldInitProactively(){return ao()||ah()||an()}};class cd{constructor(a){this.factorId=a}_process(a,b,c){switch(b.type){case"enroll":return this._finalizeEnroll(a,b.credential,c);case"signin":return this._finalizeSignIn(a,b.credential);default:return u("unexpected MultiFactorSessionType")}}}class ce extends cd{constructor(a){super("phone"),this.credential=a}static _fromCredential(a){return new ce(a)}_finalizeEnroll(a,b,c){var d,e;return d=a,G(d,"POST","/v2/accounts/mfaEnrollment:finalize",F(d,e={idToken:b,displayName:c,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}_finalizeSignIn(a,b){var c,d;return c=a,G(c,"POST","/v2/accounts/mfaSignIn:finalize",F(c,d={mfaPendingCredential:b,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}}(class{constructor(){}static assertion(a){return ce._fromCredential(a)}}).FACTOR_ID="phone";var cf="@firebase/auth",cg="0.20.5";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ class ch{constructor(a){this.auth=a,this.internalListeners=new Map}getUid(){var a;return this.assertAuthConfigured(),(null===(a=this.auth.currentUser)|| void 0===a?void 0:a.uid)||null}async getToken(a){if(this.assertAuthConfigured(),await this.auth._initializationPromise,!this.auth.currentUser)return null;let b=await this.auth.currentUser.getIdToken(a);return{accessToken:b}}addAuthTokenListener(a){if(this.assertAuthConfigured(),this.internalListeners.has(a))return;let b=this.auth.onIdTokenChanged(b=>{var c;a((null===(c=b)|| void 0===c?void 0:c.stsTokenManager.accessToken)||null)});this.internalListeners.set(a,b),this.updateProactiveRefresh()}removeAuthTokenListener(a){this.assertAuthConfigured();let b=this.internalListeners.get(a);b&&(this.internalListeners.delete(a),b(),this.updateProactiveRefresh())}assertAuthConfigured(){t(this.auth._initializationPromise,"dependent-sdk-initialized-before-auth")}updateProactiveRefresh(){this.internalListeners.size>0?this.auth._startProactiveRefresh():this.auth._stopProactiveRefresh()}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Returns the Auth instance associated with the provided {@link @firebase/app#FirebaseApp}.
 * If no instance exists, initializes an Auth instance with platform-specific default dependencies.
 *
 * @param app - The Firebase App.
 *
 * @public
 */ function ci(a=(0,f.Mq)()){let b=(0,f.qX)(a,"auth");return b.isInitialized()?b.getImmediate():/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ /**
 * Initializes an {@link Auth} instance with fine-grained control over
 * {@link Dependencies}.
 *
 * @remarks
 *
 * This function allows more control over the {@link Auth} instance than
 * {@link getAuth}. `getAuth` uses platform-specific defaults to supply
 * the {@link Dependencies}. In general, `getAuth` is the easiest way to
 * initialize Auth and works for most use cases. Use `initializeAuth` if you
 * need control over which persistence layer is used, or to minimize bundle
 * size if you're not using either `signInWithPopup` or `signInWithRedirect`.
 *
 * For example, if your app only uses anonymous accounts and you only want
 * accounts saved for the current session, initialize `Auth` with:
 *
 * ```js
 * const auth = initializeAuth(app, {
 *   persistence: browserSessionPersistence,
 *   popupRedirectResolver: undefined,
 * });
 * ```
 *
 * @public
 */ function(a,b){let c=(0,f.qX)(a,"auth");if(c.isInitialized()){let d=c.getImmediate(),g=c.getOptions();if((0,e.vZ)(g,null!=b?b:{}))return d;o(d,"already-initialized")}let h=c.initialize({options:b});return h}(a,{popupRedirectResolver:cc,persistence:[bx,bf,bh]})}d="Browser",(0,f.Xd)(new i.wA("auth",(a,{options:b})=>{let c=a.getProvider("app").getImmediate(),e=a.getProvider("heartbeat"),{apiKey:f,authDomain:g}=c.options;return((a,c)=>{t(f&&!f.includes(":"),"invalid-api-key",{appName:a.name}),t(!(null==g?void 0:g.includes(":")),"argument-error",{appName:a.name});let e={apiKey:f,authDomain:g,clientPlatform:d,apiHost:"identitytoolkit.googleapis.com",tokenApiHost:"securetoken.googleapis.com",apiScheme:"https",sdkClientVersion:ap(d)},h=new aq(a,c,e);return function(a,b){let c=(null==b?void 0:b.persistence)||[],d=(Array.isArray(c)?c:[c]).map(x);(null==b?void 0:b.errorMap)&&a._updateErrorMap(b.errorMap),a._initializeWithPersistence(d,null==b?void 0:b.popupRedirectResolver)}(h,b),h})(c,e)},"PUBLIC").setInstantiationMode("EXPLICIT").setInstanceCreatedCallback((a,b,c)=>{let d=a.getProvider("auth-internal");d.initialize()})),(0,f.Xd)(new i.wA("auth-internal",a=>{var b;let c=ar(a.getProvider("auth").getImmediate());return b=c,new ch(b)},"PRIVATE").setInstantiationMode("EXPLICIT")),(0,f.KN)(cf,cg,/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ function(a){switch(a){case"Node":return"node";case"ReactNative":return"rn";case"Worker":return"webworker";case"Cordova":return"cordova";default:return}}(d)),(0,f.KN)(cf,cg,"esm2017")}}])