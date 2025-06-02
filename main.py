import os
import time
import json
import traceback
import base64
from datetime import datetime, timedelta

import ssl
import httpx
import numpy as np
import cv2
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ========== 配置区 ============
USERNAME = os.environ.get("SZU_USER", "2410xxxxxx")  # 这里填入您的学号
PASSWORD = os.environ.get("SZU_PWD", "your_actual_password")  # 这里填入您的密码
SERVERCHAN_KEY = [os.environ.get("SERVERCHAN_KEY", "SCT123456abcdeFGHJKLMNopqrstUVWXYZ")]  # 这里填入您的Server酱密钥（访问：https://sct.ftqq.com/r/10928获取）

# ========== 参数区 ============
API_URL = "http://swzx.szu.edu.cn/back/electricity-log/list-self?current=1&pageSize=30"
HEADERS_BASE = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Referer": "http://swzx.szu.edu.cn/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63090c33) XWEB/13639 Flue",
}

DEFAULT_CIPHERS = ":".join([
    "ECDHE+AESGCM",
    "ECDHE+CHACHA20",
    "DHE+AESGCM",
    "DHE+CHACHA20",
    "ECDH+AESGCM",
    "DH+AESGCM",
    "ECDH+AES",
    "DH+AES",
    "RSA+AESGCM",
    "RSA+AES",
    "!aNULL",
    "!eNULL",
    "!MD5",
    "!DSS",
])

ssl_context = ssl.create_default_context()
ssl_context.set_ciphers(DEFAULT_CIPHERS)

def get_httpx_client(timeout=10, follow_redirects=False):
    return httpx.Client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        transport=httpx.HTTPTransport(verify=ssl_context)
    )

# ======= 滑块相关 ==============
class SlideCrack(object):
    def __init__(self, gap_img, bg_img):
        self.gap = gap_img
        self.bg = bg_img

    @staticmethod
    def _is_path(img):
        return isinstance(img, str)

    def clear_white(self, img):
        if self._is_path(img):
            img = cv2.imread(img)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        ret, binary = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
        contours, hierarchy = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if not contours:
            return img
        cnt = max(contours, key=cv2.contourArea)
        x, y, w, h = cv2.boundingRect(cnt)
        return img[y:y + h, x:x + w]

    def template_match(self, tpl, target):
        th, tw = tpl.shape[:2]
        result = cv2.matchTemplate(target, tpl, cv2.TM_CCOEFF_NORMED)
        min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
        return max_loc[0]

    @staticmethod
    def image_edge_detection(img):
        blurred = cv2.GaussianBlur(img, (5, 5), 0)
        edges = cv2.Canny(blurred, 100, 200)
        return edges

    def discern(self):
        gap_img = self.gap if not self._is_path(self.gap) else cv2.imread(self.gap)
        bg_img = self.bg if not self._is_path(self.bg) else cv2.imread(self.bg)
        gap_processed = self.clear_white(gap_img)
        gap_gray = cv2.cvtColor(gap_processed, cv2.COLOR_BGR2GRAY)
        gap_edge = self.image_edge_detection(gap_gray)
        gap_edge_rgb = cv2.cvtColor(gap_edge, cv2.COLOR_GRAY2BGR)
        bg_gray = cv2.cvtColor(bg_img, cv2.COLOR_BGR2GRAY)
        bg_edge = self.image_edge_detection(bg_gray)
        bg_edge_rgb = cv2.cvtColor(bg_edge, cv2.COLOR_GRAY2BGR)
        x_offset = self.template_match(bg_edge_rgb, gap_edge_rgb)
        return x_offset

def encrypt_password(password, salt):
    import random
    def random_string(length):
        chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
        return ''.join(random.choice(chars) for _ in range(length))
    random_prefix = random_string(64)
    iv = random_string(16)
    plain_text = random_prefix + password
    key = salt.encode('utf-8')
    iv_bytes = iv.encode('utf-8')
    plain_bytes = plain_text.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
    padded_data = pad(plain_bytes, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    encrypted_str = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_str

def download_captcha_images(session, captcha_url, headers):
    response = session.get(captcha_url, headers=headers)
    if response.status_code != 200:
        return None, None, None
    data = response.json()
    if not (response.status_code == 200 and "isNeed" in data and data["isNeed"]):
        return "no_need", None, None
    bg_url = data.get('smallImage', '')
    gap_url = data.get('bigImage', '')
    if not bg_url or not gap_url:
        return None, None, None
    bg_data = base64.b64decode(bg_url)
    gap_data = base64.b64decode(gap_url)
    bg_img = cv2.imdecode(np.frombuffer(bg_data, np.uint8), cv2.IMREAD_COLOR)
    gap_img = cv2.imdecode(np.frombuffer(gap_data, np.uint8), cv2.IMREAD_COLOR)
    return "need", bg_img, gap_img

def verify_captcha(session, verify_url, offset, headers):
    data = {
        'canvasLength': '280',
        'moveLength': str(int(offset / 2))
    }
    verify_headers = headers.copy()
    verify_headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8'
    response = session.post(verify_url, data=data, headers=verify_headers)
    try:
        result = response.json()
        if result.get('errorCode') == 1:
            return True, None
        else:
            return False, None
    except Exception:
        return False, None

# ========== 登录&cookie获取 ===========
def get_szu_cookies():
    print("[LOGIN] Step 1: 访问统一认证中心登录入口 ...")
    with get_httpx_client(follow_redirects=False) as session:
        initial_url = "http://swzx.szu.edu.cn/back/login-center?front=http%3A%2F%2Fswzx.szu.edu.cn%2F%23%2Fpages%2Felectricity%2Fszu-electricity-view"
        response = session.get(initial_url)
        print(f"[LOGIN] 请求登录中心，返回状态: {response.status_code}")
        if response.status_code != 302:
            print(f"[LOGIN-ERROR] 期望302跳转，实际{response.status_code}")
            return None
        swzx_jessesionid = session.cookies.get('SWZX_JESSESIONID', default=None)
        print(f"[LOGIN] 当前JSESSIONID: {swzx_jessesionid}")
        if not swzx_jessesionid:
            print("[LOGIN-ERROR] 未能获取SWZX_JESSESIONID")
            return None
        cas_url = response.headers['Location']
        print(f"[LOGIN] 跟随跳转获取CAS认证页面: {cas_url}")

        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Host': 'authserver.szu.edu.cn',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
            'sec-ch-ua': '"Chromium";v="136", "Microsoft Edge";v="136", "Not.A/Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        response = session.get(cas_url, headers=headers)
        print(f"[LOGIN] CAS页面请求，状态码: {response.status_code}")
        soup = BeautifulSoup(response.text, 'html.parser')
        execution_input = soup.find('input', {'name': 'execution'})
        if not execution_input or not execution_input.get('value'):
            print("[LOGIN-ERROR] 页面上未能找到 execution 参数")
            print(f"[LOGIN-ERROR] response.text: {response.text}")
            return None
        pwdEncryptSalt_input = soup.find('input', {'id': 'pwdEncryptSalt'})
        if not pwdEncryptSalt_input or not pwdEncryptSalt_input.get('value'):
            print("[LOGIN-ERROR] 页面上未能找到 pwdEncryptSalt 参数")
            return None
        execution = execution_input['value']
        pwdEncryptSalt = pwdEncryptSalt_input['value']
        print(f"[LOGIN] 提取 execution={execution[:10]}..., pwdEncryptSalt={pwdEncryptSalt[:10]}...")

        # 滑块验证码判断
        captcha_headers = {
            'User-Agent': HEADERS_BASE['User-Agent'],
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': 'https://authserver.szu.edu.cn',
            'Referer': cas_url,
            'X-Requested-With': 'XMLHttpRequest'
        }
        captcha_url = 'https://authserver.szu.edu.cn/authserver/common/openSliderCaptcha.htl'
        verify_url = 'https://authserver.szu.edu.cn/authserver/common/verifySliderCaptcha.htl'
        print("[LOGIN] 检查是否存在滑块验证码 ...")
        try:
            captcha_type, bg_img, gap_img = download_captcha_images(session, captcha_url, captcha_headers)
        except Exception as e:
            print(f"[LOGIN-ERROR] 获取滑块接口异常: {e}")
            return None

        captcha_verified = False
        if captcha_type == "need":
            print("[LOGIN] 发现需要滑块验证码，准备识别处理 ...")
            try:
                sc = SlideCrack(gap_img, bg_img)
                offset = sc.discern()
                print(f"[LOGIN] 滑块AI识别偏移为: {offset}，准备提交验证")
                captcha_verified, _ = verify_captcha(session, verify_url, offset, captcha_headers)
            except Exception as e:
                print(f"[LOGIN-ERROR] 滑块识别处理异常: {e}")
                return None
            print(f"[LOGIN] 滑块验证结果：{'通过' if captcha_verified else '未通过，尝试继续'}")
        elif captcha_type == "no_need":
            print("[LOGIN] 后端返回无需滑块验证码，直接进入登录")
        else:
            print("[LOGIN] 滑块接口未知情况，继续尝试登录")

        login_url = "https://authserver.szu.edu.cn/authserver/login?service=http%3A%2F%2Fswzx.szu.edu.cn%2Fback%2Flogin%2Fcas"
        encrypted_password = encrypt_password(PASSWORD, pwdEncryptSalt)
        payload = {
            'username': USERNAME,
            'password': encrypted_password,
            'captcha': '',
            'rememberMe': 'false',
            '_eventId': 'submit',
            'cllt': 'userNameLogin',
            'dllt': 'generalLogin',
            'lt': '',
            'execution': execution
        }
        session.cookies.set("org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE", "zh_CN")
        login_headers = {
            'User-Agent': HEADERS_BASE['User-Agent'],
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://authserver.szu.edu.cn',
            'Referer': cas_url
        }
        print("[LOGIN] 提交登录表单 ...")
        response = session.post(login_url, data=payload, headers=login_headers, follow_redirects=False)
        print(f"[LOGIN] 登录提交 POST 返回: {response.status_code}")
        if response.status_code != 302:
            print(f"[LOGIN-ERROR] 登录失败，期望302实际{response.status_code}")
            try:
                print(f"[LOGIN-ERROR] 返回页面摘要：{response.text[:200]}...")
            except Exception:
                pass
            return None
        ticket_url = response.headers['Location']
        print(f"[LOGIN] 登陆成功，获得ticket跳转：{ticket_url}")

        ticket_headers = {
            'User-Agent': HEADERS_BASE['User-Agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Referer': 'https://authserver.szu.edu.cn/'
        }
        response = session.get(ticket_url, headers=ticket_headers, follow_redirects=False)
        print(f"[LOGIN] 跟ticket跳转, 状态码: {response.status_code}")
        if response.status_code != 302:
            print("[LOGIN-ERROR] ticket跳转失败")
            return None
        final_url = response.headers['Location']
        print(f"[LOGIN] 最终服务端跳转: {final_url}")
        response = session.get(final_url, headers=ticket_headers, follow_redirects=False)
        cookies = session.cookies
        tk = cookies.get('_tk', default=None)
        print(f"[LOGIN] 登录后cookie：_tk={tk}, SWZX_JESSESIONID={swzx_jessesionid}")
        if not tk:
            print("[LOGIN-ERROR] 没有获得_tk")
            return None
        print("[LOGIN] 登录流程完毕，可以正常调用查电费API。")
        return dict(SWZX_JESSESIONID=swzx_jessesionid, _tk=tk)

# ========== 电费和推送 ==========
def http_get(url, headers=None, timeout=10):
    try:
        with get_httpx_client(timeout) as client:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.text
    except Exception as e:
        print(f"http_get异常: {e}")
        return None

def http_post(url, data_dict, headers=None, timeout=10):
    try:
        with get_httpx_client(timeout) as client:
            resp = client.post(url, data=data_dict, headers=headers)
            resp.raise_for_status()
            return resp.text
    except Exception as e:
        print(f"http_post异常: {e}")
        return None

def get_latest_electric_fee(cookies):
    headers = HEADERS_BASE.copy()
    cookie_str = f"SWZX_JESSESIONID={cookies['SWZX_JESSESIONID']}; _tk={cookies['_tk']}"
    headers["Cookie"] = cookie_str
    txt = http_get(API_URL, headers)
    if not txt:
        return None, []
    try:
        resp = json.loads(txt)
        items = resp["data"]["list"]
        if not items:
            return None, []
        items_sorted = sorted(items, key=lambda x: x["date"], reverse=True)
        latest = items_sorted[0]
        latest_date = datetime.strptime(latest["date"], "%Y-%m-%d")
        days_ago = (datetime.now() - latest_date).days
        history = sorted(items, key=lambda x: x["date"])
        dates = [datetime.strptime(d['date'], "%Y-%m-%d") for d in history]
        used_values = [d['used'] for d in history]
        remainings = [d['remaining'] for d in history]
        return {
            "date": latest["date"],
            "days_ago": days_ago,
            "remaining": latest["remaining"],
            "used": latest["used"]
        }, (dates, used_values, remainings)
    except Exception as e:
        print(f"获取电费异常: {e}")
        return None, []

def predict_future(dates, used_values, remainings, days_predict=6):
    if not dates or not used_values or len(dates) < 2:
        return "历史数据不足无法预测", "未知"
    daily_usage = []
    for i in range(1, len(used_values)):
        usage = used_values[i] - used_values[i - 1]
        if usage > 0:
            daily_usage.append(usage)
    if len(daily_usage) < 5:
        avg_daily_usage = sum(daily_usage) / max(1, len(daily_usage))
    else:
        recent_usage = daily_usage[-14:] if len(daily_usage) > 14 else daily_usage
        avg_daily_usage = sum(recent_usage) / len(recent_usage)
    latest_remaining = remainings[-1]
    future_dates = [dates[-1] + timedelta(days=i + 1) for i in range(days_predict)]
    future_remainings = []
    for i in range(days_predict):
        pred_remaining = latest_remaining - avg_daily_usage*(i+1)
        future_remainings.append(pred_remaining)
    zero_day = f"未来{days_predict / 2}天内不会"
    for date, pred_rem in zip(future_dates, future_remainings):
        if pred_rem < 0:
            zero_day = date.strftime("%Y-%m-%d")
            break
    prediction_table = ""
    for d, r in zip(future_dates, future_remainings):
        prediction_table += f"{d.strftime('%Y-%m-%d')} 预测剩余: {r:.2f} 度\n"
    result = f"前后{days_predict / 2}天预测：\n{prediction_table}\n预计欠费日：{zero_day}"
    return result, zero_day

def send_serverchan(title, content):
    for key in SERVERCHAN_KEY:
        if not key or key == 'None':
            continue
        url = f"https://sctapi.ftqq.com/{key}.send"
        data = {
            "title": title,
            "desp": content
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = http_post(url, data, headers)
        print(f"推送状态: {resp}")

def job_logic(debug=False):
    cookies = get_szu_cookies()
    if not cookies:
        send_serverchan("电费获取失败", f"**日期：** {datetime.now().strftime('%Y-%m-%d')}\n\n登录或cookie获取失败，请检查帐号/密码/验证码。") if not debug else None
        return
    info, data = get_latest_electric_fee(cookies)
    if data:
        dates, used_values, remainings = data
    else:
        dates, used_values, remainings = [], [], []
    today = datetime.now().strftime('%Y-%m-%d')
    if info is None:
        send_serverchan("电费获取失败", f"**日期：** {today}\n\n未获取到电费信息，请检查接口或Cookie等配置。") if not debug else None
        return
    prediction_msg, zero_day = predict_future(dates, used_values, remainings)
    h = datetime.now().hour
    prediction_msg_for_text = prediction_msg.replace(chr(10), '  \n')
    notify_text = (
        f"**最新抄表日期：** {info['date']}（{info['days_ago']}天前）\n\n"
        f"**剩余电费：** {info['remaining']} 度\n\n"
        f"**累计用电量：** {info['used']} 度\n\n"
        f"{prediction_msg_for_text}"
    )
    title = (
        f"⚠️电费不足！剩{info['remaining']}度，预计[{zero_day}]欠费"
        if info["remaining"] < 20
        else f"电费剩余{info['remaining']}度"
    )
    print(f"title: {title}")
    print(f"notify_text: {notify_text}")
    if info["remaining"] < 20:
        send_serverchan(title, notify_text) if not debug else None
    else:
        if h == 18:
            send_serverchan(title, notify_text) if not debug else None

def wait_until_next_target():
    now = datetime.now()
    today_targets = [0, 6, 12, 18, 22]
    targets = [now.replace(hour=h, minute=0, second=0, microsecond=0) for h in today_targets]
    next_times = [t for t in targets if t > now]
    if not next_times:
        next_time = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        next_time = next_times[0]
    wait_s = (next_time - now).total_seconds()
    print(f"下次任务时间：{next_time}，距离现在还有{int(wait_s)}秒。")
    return max(1, int(wait_s))

if __name__ == "__main__":
    print("【电费通知守护进程启动】")

    mode = "run"
    if mode == "debug":
        job_logic(debug=True)
    else:
        last_job_run = None
        while True:
            try:
                now = datetime.now()
                h = now.hour
                m = now.minute
                if h in [0, 6, 12, 18, 22] and m == 0:
                    if last_job_run != (now.date(), h):
                        print(f"\n{now} 执行定时检查...")
                        job_logic()
                        last_job_run = (now.date(), h)
                    else:
                        print(f"{now}: 已执行过，无需重复")
                    time.sleep(65)
                else:
                    sleep_time = min(wait_until_next_target(), 60)
                    time.sleep(sleep_time)
            except Exception as e:
                print("主循环异常：", e)
                traceback.print_exc()
                time.sleep(30)
