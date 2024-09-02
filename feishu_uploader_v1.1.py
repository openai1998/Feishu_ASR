import base64
import configparser
import os
import time
import uuid
import zlib
import json
import hashlib
from datetime import datetime
from concurrent.futures import as_completed, ThreadPoolExecutor

import requests
from tqdm import tqdm
import pandas as pd
import re
import logging
import sys

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')
logger = logging.getLogger(__name__)

# 设置控制台输出编码
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# 读取配置文件
config = configparser.ConfigParser(interpolation=None)
config.read('config.ini', encoding='utf-8')
minutes_cookie = config.get('Cookies', 'minutes_cookie')
directory = config.get('上传设置', '要上传的文件所在路径')
use_proxy = config.get('代理设置', '是否使用代理（是/否）')
proxy_address = config.get('代理设置', '代理地址')
proxies = {'http': proxy_address, 'https': proxy_address} if use_proxy == '是' else None

# 日志文件路径
LOG_FILE = 'upload_log.json'
EXCEL_FILE = 'upload_records.xlsx'
DUPLICATE_LOG_FILE = 'duplicate_log.json'
TEMP_DB_FILE = 'temp_cloud_videos.json'
DAILY_LIMIT = 10000
MAX_RETRIES = 3

def calculate_file_hash(file_path):
    """计算文件的MD5哈希值"""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def load_excel_log():
    """加载Excel日志文件"""
    if os.path.exists(EXCEL_FILE):
        return pd.read_excel(EXCEL_FILE)
    else:
        df = pd.DataFrame(columns=['视频名称', '原始文件名', '哈希', '上传日期', 'URL'])
        df.to_excel(EXCEL_FILE, index=False)
        return df

def save_excel_log(df):
    """保存Excel日志文件"""
    df.to_excel(EXCEL_FILE, index=False)

def load_duplicate_log():
    """加载重复上传日志"""
    if os.path.exists(DUPLICATE_LOG_FILE):
        with open(DUPLICATE_LOG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_duplicate_log(duplicate_data):
    """保存重复上传日志"""
    with open(DUPLICATE_LOG_FILE, 'w') as f:
        json.dump(duplicate_data, f, indent=2)

def load_temp_db():
    """加载临时数据库"""
    if os.path.exists(TEMP_DB_FILE):
        with open(TEMP_DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_temp_db(data):
    """保存临时数据库"""
    with open(TEMP_DB_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def delete_temp_db():
    """删除临时数据库"""
    if os.path.exists(TEMP_DB_FILE):
        os.remove(TEMP_DB_FILE)

class FeishuUploader:
    def __init__(self, file_path=None, cookie=None):
        self.file_path = file_path
        self.block_size = 2**20*4
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
            'cookie': cookie,
            'bv-csrf-token': self._extract_csrf_token(cookie),
            'referer': 'https://meetings.feishu.cn/minutes/me',
            'content-type': 'application/x-www-form-urlencoded'
        }
        self.upload_token = None
        self.vhid = None
        self.upload_id = None
        self.object_token = None

        if file_path:
            with open(self.file_path, 'rb') as f:
                self.file_size = f.seek(0, 2)
                f.seek(0)
                self.file_header = base64.b64encode(f.read(512)).decode()

    def _extract_csrf_token(self, cookie):
        token = cookie[cookie.find('bv_csrf_token=') + len('bv_csrf_token='):cookie.find(';', cookie.find('bv_csrf_token='))]
        if len(token) != 36:
            raise ValueError("minutes_cookie中不包含bv_csrf_token，请确保从请求`list?size=20&`中获取！")
        return token

    def get_cloud_videos(self):
        """
        批量获取妙记信息
        """
        get_rec_url = f'https://meetings.feishu.cn/minutes/api/space/list?size=1000'
        logger.debug("正在从URL获取妙记: %s", get_rec_url)
        
        try:
            resp = requests.get(url=get_rec_url, headers=self.headers, proxies=proxies)
            resp.raise_for_status()
            data = resp.json()
            
            if 'list' not in data.get('data', {}):
                raise ValueError("minutes_cookie失效，请重新获取！")
            
            logger.info("成功获取到 %d 条妙记", len(data['data']['list']))
            for minute in data['data']['list'][:5]:  # 只打印前5条，避免日志过长
                logger.debug(f"妙记信息: {minute}")
            
            return {minute['topic']: minute['object_token'] for minute in data['data']['list']}
        except requests.exceptions.RequestException as e:
            logger.error("获取妙记时发生错误: %s", str(e))
            logger.debug("响应内容: %s", e.response.text if e.response else '无响应')
            return {}

    def get_quota(self):
        file_info = f'{uuid.uuid1()}_{self.file_size}'
        quota_url = f'https://meetings.feishu.cn/minutes/api/quota?file_info[]={file_info}&language=zh_cn'
        quota_res = requests.get(quota_url, headers=self.headers, proxies=proxies).json()
        if quota_res['data']['has_quota'] == False:
            raise Exception("飞书妙记空间已满，请清理后重试！")
        self.upload_token = quota_res['data']['upload_token'][file_info]

    def prepare_upload(self):
        file_name = os.path.basename(self.file_path)
        if '.' in file_name:
            file_name = file_name[:file_name.rfind('.')]
        prepare_url = f'https://meetings.feishu.cn/minutes/api/upload/prepare'
        json = {
            'name': file_name,
            'file_size': self.file_size,
            'file_header': self.file_header,
            'drive_upload': True,
            'upload_token': self.upload_token,
        }
        prepare_res = requests.post(prepare_url, headers=self.headers, proxies=proxies, json=json).json()
        self.vhid = prepare_res['data']['vhid']
        self.upload_id = prepare_res['data']['upload_id']
        self.object_token = prepare_res['data']['object_token']

    def upload_blocks(self):
        with open(self.file_path, 'rb') as f:
            f.seek(0)
            block_count = (self.file_size + self.block_size - 1) // self.block_size
            with ThreadPoolExecutor(max_workers=1) as executor:
                completed_threads = []
                with tqdm(total=block_count, unit='block') as progress_bar:
                    for i in range(block_count):
                        block_data = f.read(self.block_size)
                        block_size = len(block_data)
                        checksum = zlib.adler32(block_data) & 0xffffffff
                        upload_url = f'https://internal-api-space.feishu.cn/space/api/box/stream/upload/block?upload_id={self.upload_id}&seq={i}&size={block_size}&checksum={checksum}'
                        thread = executor.submit(self.upload_block_with_retry, upload_url, block_data)
                        completed_threads.append(thread)
                        time.sleep(0.2)
                    for thread in as_completed(completed_threads):
                        progress_bar.update(1)

    def upload_block_with_retry(self, url, data):
        for attempt in range(MAX_RETRIES):
            try:
                response = requests.post(url, headers=self.headers, proxies=proxies, data=data)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    raise Exception(f"上传块失败，已重试{MAX_RETRIES}次: {str(e)}")
                time.sleep(2 ** attempt)  # 指数退避

    def complete_upload(self):
        complete_url1 = f'https://internal-api-space.feishu.cn/space/api/box/upload/finish/'
        json = {
            'upload_id': self.upload_id,
            'num_blocks': (self.file_size + self.block_size - 1) // self.block_size,
            'vhid': self.vhid,
            'risk_detection_extra' : '{\"source_terminal\":1,\"file_operate_usage\":3,\"locale\":\"zh_cn\"}'
        }
        resp = requests.post(complete_url1, headers=self.headers, proxies=proxies, json=json).json()
        if resp.get('code') != 0:
            raise Exception(f"完成上传第一步失败: {resp}")

        complete_url2 = f'https://meetings.feishu.cn/minutes/api/upload/finish'
        json = {
            'auto_transcribe': True,
            'language': 'mixed',
            'num_blocks': (self.file_size + self.block_size - 1) // self.block_size,
            'upload_id': self.upload_id,
            'vhid': self.vhid,
            'upload_token': self.upload_token,
            'object_token': self.object_token,
        }
        resp = requests.post(complete_url2, headers=self.headers, proxies=proxies, json=json).json()
        if resp.get('code') != 0:
            raise Exception(f"完成上传第二步失败: {resp}")

        return self.wait_for_transcription()

    def wait_for_transcription(self):
        start_time = time.time()
        # 临时禁用详细的调试日志
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        while True:
            time.sleep(3)
            object_status_url = f'https://meetings.feishu.cn/minutes/api/batch-status?object_token[]={self.object_token}&language=zh_cn'
            object_status = requests.get(object_status_url, headers=self.headers, proxies=proxies).json()
            transcript_progress = object_status['data']['status'][0]['transcript_progress']
            spend_time = time.time() - start_time
            if object_status['data']['status'][0]['object_status'] == 2 or transcript_progress['current'] == '':
                # 恢复详细的调试日志
                logging.getLogger("urllib3").setLevel(logging.DEBUG)
                return f"http://meetings.feishu.cn/minutes/{object_status['data']['status'][0]['object_token']}"
            print(f"转写中...已用时{spend_time:.2f}秒\r", end='')

    def upload(self):
        self.get_quota()
        self.prepare_upload()
        self.upload_blocks()
        return self.complete_upload()

def get_video_files(directory):
    video_extensions = ('.mp4', '.avi', '.mov', '.mkv', '.flv')
    video_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(video_extensions):
                video_files.append(os.path.join(root, file))
    return video_files

def load_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            return json.load(f)
    return {'last_upload_date': '', 'daily_count': 0, 'uploaded_files': {}}

def save_log(log_data):
    with open(LOG_FILE, 'w') as f:
        json.dump(log_data, f, indent=2)

def sanitize_filename(filename):
    # 移除文件扩展名
    filename = os.path.splitext(filename)[0]
    # 移除方括号及其内容，例如 [P02]
    filename = re.sub(r'\[.*?\]', '', filename)
    # 解码 Unicode 转义序列
    filename = filename.encode('utf-8').decode('unicode_escape')
    # 移除多余的空格
    filename = ' '.join(filename.split())
    return filename.strip()

def main():
    log_data = load_log()
    excel_log = load_excel_log()
    duplicate_log = load_duplicate_log()
    today = datetime.now().strftime('%Y-%m-%d')
    
    if log_data['last_upload_date'] != today:
        log_data['last_upload_date'] = today
        log_data['daily_count'] = 0

    # 获取视频文件列表
    video_files = get_video_files(directory)
    logger.info(f"找到 {len(video_files)} 个视频文件")
    
    # 获取云端视频列表并存储到临时数据库
    uploader = FeishuUploader(cookie=minutes_cookie)
    cloud_videos = uploader.get_cloud_videos()
    save_temp_db(cloud_videos)
    
    for file_path in tqdm(video_files, desc="上传视频", unit="file"):
        file_hash = calculate_file_hash(file_path)
        original_video_name = os.path.basename(file_path)
        
        # 本地去重验证
        if file_hash in log_data['uploaded_files']:
            logger.info("跳过已上传的文件: %s", original_video_name)
            continue

        # 云端去重验证
        if original_video_name in cloud_videos:
            logger.info("云端已存在文件: %s", original_video_name)
            duplicate_log[file_hash] = {
                'local_path': file_path,
                'cloud_name': original_video_name,
                'cloud_url': f"http://meetings.feishu.cn/minutes/{cloud_videos[original_video_name]}",
                'date': today
            }
            save_duplicate_log(duplicate_log)
            continue

        if log_data['daily_count'] >= DAILY_LIMIT:
            logger.info("已达到每日上传限制 %d。请等待明天继续上传。", DAILY_LIMIT)
            break

        logger.info("正在上传: %s", original_video_name)
        file_uploader = FeishuUploader(file_path=file_path, cookie=minutes_cookie)
        try:
            url = file_uploader.upload()
            logger.info("%s 上传完成，URL: %s", original_video_name, url)
            log_data['daily_count'] += 1
            log_data['uploaded_files'][file_hash] = {
                'file_path': file_path,
                'video_name': original_video_name,
                'original_name': original_video_name,
                'url': url,
                'upload_date': today
            }
            save_log(log_data)
            # 更新Excel日志
            new_row = pd.DataFrame([{'视频名称': original_video_name, '原始文件名': original_video_name, '哈希': file_hash, '上传日期': today, 'URL': url}])
            excel_log = pd.concat([excel_log, new_row], ignore_index=True)
            save_excel_log(excel_log)
        except Exception as e:
            logger.error("上传 %s 时发生错误: %s", original_video_name, str(e))
        time.sleep(0.2)

    # 删除临时数据库
    delete_temp_db()
    logger.info("所有文件上传完成或已达到每日限制")

if __name__ == '__main__':
    main()