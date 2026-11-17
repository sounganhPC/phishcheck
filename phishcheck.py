# phishcheck.py — 링크 안전 검사기 (한국 타겟 피싱 전용)
# 원칙: 절대 링크를 방문하지 않음. DNS/RDAP/IP조회/패턴 분석 등 수동 조회만으로 판정
# 사용: python phishcheck.py <url> [--json]
import sys, json, re, socket, argparse, datetime
import requests, tldextract
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

UA = {"User-Agent": "sounganh-phishcheck/1.0 (+security check)"}

# 무료 동적DNS/임시도메인 (피싱 상용구)
DDNS = {"dynu.net","duckdns.org","no-ip.com","ddns.net","hopto.org","dyndns.org",
        "zapto.org","servehttp.com","bounceme.net","myvnc.com","blogdns.com",
        "gotdns.com","ddnsking.com","is-a.dev","repl.co","trycloudflare.com",
        "workers.dev","web.app","firebaseapp.com","glitch.me","netlify.app"}
# 단축URL (펼치기 전까지 판정 보류)
SHORTENERS = {"bit.ly","t.co","tinyurl.com","cutt.ly","rebrand.ly","shorturl.at",
              "vo.la","me2.do","naver.me","rb.gy","url.kr"}
# 한국 공식/신뢰 접미사·도메인
GOV_SUFFIX = (".go.kr", ".korea.kr", ".mil.kr", ".or.kr", ".re.kr", ".pe.kr")
TRUSTED = {"naver.com","kakao.com","daum.net","google.com","youtube.com",
           "nate.com","coupang.com","microsoft.com","apple.com","github.com"}
SUS_KW = ["verify","login","signin","account","echk","confirm","secure","update",
          "billing","support","webscr","auth","check","suspend","unlock","eps"]

def rdap_domain(domain):
    """등록일 조회 (kr→nida, com/net→verisign). 실패시 None."""
    try:
        if domain.endswith(".kr"):
            url = f"https://rdap.nida.or.kr/rdap/domain/{domain}"
        elif domain.endswith((".com", ".net")):
            url = f"https://rdap.verisign.com/v1/domain/{domain.upper()}"
        else:
            return None
        r = requests.get(url, headers=UA, timeout=10)
        for ev in r.json().get("events", []):
            if ev.get("eventAction") in ("registration", "registered"):
                return datetime.date.fromisoformat(ev["eventDate"][:10])
    except Exception:
        return None

def geoip(ip):
    try:
        d = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org",
                         headers=UA, timeout=8).json()
        return d if d.get("status") == "success" else None
    except Exception:
        return None

def check(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    ext = tldextract.extract(url)
    domain = ext.top_domain_under_public_suffix or ext.fqdn
    sub = ext.subdomain
    host = ext.fqdn or domain
    score, reasons = 0, []

    def hit(pts, msg):
        nonlocal score
        score += pts
        reasons.append(f"{'+' if pts>0 else ''}{pts}점: {msg}")

    # 1. IP 직접 접속
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        hit(50, "도메인 대신 IP 직접 접속")

    # 2. 공식/신뢰 도메인
    if domain.endswith(GOV_SUFFIX):
        hit(-60, f"한국 공식 도메인 ({domain})")
    if domain in TRUSTED:
        hit(-40, f"신뢰 도메인 ({domain})")

    # 3. 무료DDNS / 단축
    if domain in DDNS:
        hit(45, f"무료 동적DNS 도메인 ({domain}) — 피싱 단골, 누구나 즉석 생성 가능")
    if domain in SHORTENERS:
        hit(15, f"단축URL ({domain}) — 실제 목적지 불명, 펼쳐서 재검사 필요")

    # 4. 서브도메인 과다 / 위장
    if sub.count(".") >= 2:
        hit(10, f"서브도메인 과다 ({sub}) — 긴 주소로 진짜 도메인 숨기기")
    m = re.search(r"(naver|kakao|daum|nate|wetax|gov|hometax|kb|shinhan|woori|hana|nh)\w*\.?com|\.(go|or)\.kr\.", host)
    if m and domain not in TRUSTED and not domain.endswith(GOV_SUFFIX):
        hit(40, f"공식처럼 보이는 위장 문자열 포함: {host}")

    # 5. 의심 키워드/파라미터
    low = url.lower()
    found = [k for k in SUS_KW if k in low]
    if found:
        hit(5 * len(found), f"의심 키워드 {found}")
    if re.search(r"[?&](echk|email|mail|e)=", low) or re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", url):
        hit(20, "URL에 이메일/추적토큰 파라미터 — 클릭 추적용 피싱 전형")
    if "xn--" in host:
        hit(15, "퓨니코드 도메인 — 유사문자 위장 가능")

    # 6. 도메인 등록일
    reg = rdap_domain(domain)
    if reg:
        age = (datetime.date.today() - reg).days
        if age < 30:
            hit(40, f"도메인 생성 {age}일 — 신생(30일 미만)은 피싱 다수")
        elif age < 180:
            hit(15, f"도메인 생성 {age}일 — 반년 미만")
        else:
            hit(-10, f"도메인 생성 {age}일 — 오래됨(신뢰 신호)")

    # 7. DNS/IP 국가 (한국 공식 사칭인데 해외IP면 감점)
    try:
        ip = socket.gethostbyname(host)
        g = geoip(ip)
        if g:
            cc, org = g["countryCode"], g.get("org", "")
            reasons.append(f"정보: IP {ip} ({cc}, {org})")
            if domain.endswith(GOV_SUFFIX) is False and cc not in ("KR",):
                hit(10, f"서버 해외 위치 ({cc}) — 한국 서비스 사칭이면 의심 신호")
    except Exception:
        reasons.append("정보: DNS 해석 실패 — 죽은 도메인이거나 차단됨")
        score += 5

    verdict = "위험" if score >= 50 else ("주의" if score >= 20 else "정상")
    return {"url": url, "domain": domain, "ip_score": score, "verdict": verdict, "reasons": reasons}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = check(a.url)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        print(f"판정: {r['verdict']} ({r['ip_score']}점) - {r['domain']}")
        for x in r["reasons"]:
            print(f"  {x}")
