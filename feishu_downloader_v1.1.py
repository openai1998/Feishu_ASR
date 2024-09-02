import configparser
import locale
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
import logging
import requests
from tqdm import tqdm
import shutil
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# 设置日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

locale.setlocale(locale.LC_CTYPE, "chinese")

# 读取配置文件
config = configparser.ConfigParser(interpolation=None)
config.read('config.ini', encoding='utf-8')

# 获取配置文件中的cookie
minutes_cookie = config.get('Cookies', 'minutes_cookie')
manager_cookie = config.get('Cookies', 'manager_cookie')

# 获取下载设置
space_name = config.getint('下载设置', '所在空间')
list_size = config.getint('下载设置', '每次检查的妙记数量')
check_interval = config.getint('下载设置', '检查妙记的时间间隔（单位s，太短容易报错）')
download_type = config.getint('下载设置', '文件类型')

# 手动处理布尔值
def get_boolean(value):
    return value == '是'

subtitle_only = get_boolean(config.get('下载设置', '是否只下载字幕文件（是/否）', fallback='否'))

# 处理可能存在编码问题的选项
try:
    usage_threshold = config.getfloat('下载设置', '存储额度阈值（百分比，默认95%）（填写了manager_cookie才有效）')
except configparser.NoOptionError:
    try:
        usage_threshold = config.getfloat('下载设置', '存储额度阈值')
    except configparser.NoOptionError:
        usage_threshold = 0.95
        logger.warning("未找到存储额度阈值设置,使用默认值95%")

# 获取保存路径
save_path = os.path.abspath(config.get('下载设置', '保存路径（不填则默认为当前路径/data）', fallback='./data'))

# 获取字幕格式设置
subtitle_params = {
    'add_speaker': get_boolean(config.get('下载设置', '字幕是否包含说话人（是/否）', fallback='否')),
    'add_timestamp': get_boolean(config.get('下载设置', '字幕是否包含时间戳（是/否）', fallback='否')),
    'format': 3 if config.get('下载设置', '字幕格式（srt/txt）', fallback='txt') == 'srt' else 2
}

# 获取代理设置
use_proxy = get_boolean(config.get('代理设置', '是否使用代理（是/否）', fallback='否'))
proxy_address = config.get('代理设置', '代理地址', fallback=None)
proxies = {'http': proxy_address, 'https': proxy_address} if use_proxy else None

logger.debug("配置加载成功")

def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

class FeishuDownloader:
    def __init__(self, cookie):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
            'cookie': cookie,
            'bv-csrf-token': self._extract_csrf_token(cookie),
            'referer': 'https://meetings.feishu.cn/minutes/me',
            'content-type': 'application/x-www-form-urlencoded'
        }
        self.meeting_time_dict = {}
        self.subtitle_type = 'srt' if subtitle_params['format'] == 3 else 'txt'
        self.subtitle_params = subtitle_params.copy()  # 使用全局的 subtitle_params
        logger.debug("飞书下载器已初始化,cookie前10位: %s...", cookie[:10])

    def _extract_csrf_token(self, cookie):
        token = cookie[cookie.find('bv_csrf_token=') + len('bv_csrf_token='):cookie.find(';', cookie.find('bv_csrf_token='))]
        if len(token) != 36:
            raise ValueError("minutes_cookie中不包含bv_csrf_token，请确保从请求`list?size=20&`中获取！")
        return token

    def get_minutes(self):
        """
        批量获取妙记信息
        """
        get_rec_url = f'https://meetings.feishu.cn/minutes/api/space/list?&size={list_size}&space_name={space_name}'
        logger.debug("正在从URL获取妙记: %s", get_rec_url)
        
        try:
            resp = requests_retry_session().get(url=get_rec_url, headers=self.headers, proxies=proxies)
            resp.raise_for_status()
            data = resp.json()
            
            if 'list' not in data.get('data', {}):
                raise ValueError("minutes_cookie失效，请重新获取！")
            
            logger.info("成功获取到 %d 条妙记", len(data['data']['list']))
            for minute in data['data']['list'][:5]:  # 只打印前5条，避免日志过长
                logger.debug(f"妙记信息: {minute}")
            return list(reversed(data['data']['list']))
        except requests.exceptions.RequestException as e:
            logger.error("获取妙记时发生错误: %s", str(e))
            raise

    def check_minutes(self):
        """
        检查需要下载的妙记
        """
        logger.info("正在检查是否有新的妙记需要下载")
        
        downloaded_minutes = self._load_downloaded_minutes()
        logger.debug(f"已下载的妙记数量: {len(downloaded_minutes)}")
        logger.debug(f"已下载的妙记: {downloaded_minutes}")
        
        all_minutes = self.get_minutes()
        logger.debug(f"获取到的总妙记数量: {len(all_minutes)}")
        
        need_download_minutes = [
            minutes for minutes in all_minutes
            if minutes['object_token'] not in downloaded_minutes and
            (download_type == 2 or minutes['object_type'] == download_type)
        ]
        logger.info(f"需要下载的新妙记数量: {len(need_download_minutes)}")
        
        if not need_download_minutes:
            logger.info("没有新的妙记需要下载")
            return False

        self.download_minutes(need_download_minutes)
        return True

    def _load_downloaded_minutes(self):
        try:
            with open('downloaded_minutes.txt', 'r', encoding='utf-8') as f:
                downloaded = set(line.strip() for line in f)
            logger.debug(f"从文件加载了 {len(downloaded)} 条已下载的妙记")
            return downloaded
        except FileNotFoundError:
            logger.warning("未找到已下载妙记记录文件，将创建新文件")
            open('downloaded_minutes.txt', 'w').close()
            return set()

    def _save_downloaded_minutes(self, object_token):
        with open('downloaded_minutes.txt', 'a', encoding='utf-8') as f:
            f.write(f"{object_token}\n")
        logger.debug(f"已保存妙记: {object_token}")

    def get_minutes_url(self, minutes):
        """
        获取妙记视频下载链接；写入字幕文件。
        """
        logger.debug("正在获取妙记的URL: %s", minutes['object_token'])
        
        try:
            # 使用正确的API端点获取妙记详情
            status_url = f'https://meetings.feishu.cn/minutes/api/status?object_token={minutes["object_token"]}&language=zh_cn&_t={int(time.time() * 1000)}'
            status_resp = requests_retry_session().get(url=status_url, headers=self.headers, proxies=proxies)
            status_resp.raise_for_status()
            
            logger.debug(f"API响应内容: {status_resp.text}")
            
            status_data = status_resp.json()
            
            if 'data' not in status_data:
                logger.warning(f"妙记 {minutes['object_token']} 的响应中没有 'data' 字段")
                return None, None
            
            status_data = status_data['data']
            
            # 获取妙记视频的下载链接
            if 'video_info' in status_data and 'video_download_url' in status_data['video_info']:
                video_url = status_data['video_info']['video_download_url']
            else:
                logger.warning(f"妙记 {minutes['object_token']} 没有视频下载链接")
                return None, None

            # 获取妙记字幕
            subtitle_url = f'https://meetings.feishu.cn/minutes/api/export'
            self.subtitle_params['object_token'] = minutes['object_token']
            resp = requests_retry_session().post(url=subtitle_url, params=self.subtitle_params, headers=self.headers, proxies=proxies)
            resp.encoding = 'utf-8'

            # 确保字幕内容不为空
            if not resp.text.strip():
                logger.warning(f"妙记 {minutes['object_token']} 的字幕内容为空")
                return None, None

            # 获取妙记标题
            file_name = minutes['topic']
            rstr = r'[\/\\\:\*\?\"\<\>\|]'
            file_name = re.sub(rstr, '_', file_name)  # 将标题中的特殊字符替换为下划线
            
            # 如果妙记来自会议，则将会议起止时间作为文件名的一部分
            if minutes['object_type'] == 0:
                start_time = time.strftime("%Y年%m月%d日%H时%M分", time.localtime(minutes['start_time'] / 1000))
                stop_time = time.strftime("%Y年%m月%d日%H时%M分", time.localtime(minutes['stop_time'] / 1000))
                file_name = start_time+"至"+stop_time+file_name
            else:
                create_time = time.strftime("%Y年%m月%d日%H时%M分", time.localtime(minutes['create_time'] / 1000))
                file_name = create_time+file_name
            
            subtitle_name = file_name
                
            # 创建文件夹
            if not os.path.exists(f'{save_path}/{file_name}'):
                os.makedirs(f'{save_path}/{file_name}')

            # 写入字幕文件
            with open(f'{save_path}/{file_name}/{subtitle_name}.{self.subtitle_type}', 'w', encoding='utf-8') as f:
                f.write(resp.text)
            
            # 如果妙记来自会议，则记录会议起止时间
            if minutes['object_type'] == 0:
                self.meeting_time_dict[file_name] = minutes['start_time']/1000

            logger.debug("已处理妙记: %s", file_name)
            return video_url, file_name

        except Exception as e:
            logger.exception(f"处理妙记 {minutes['object_token']} 时发生错误: {str(e)}")
            return None, None

    def _generate_file_name(self, minutes):
        """
        生成文件名
        """
        file_name = minutes['topic']
        rstr = r'[\/\\\:\*\?\"\<\>\|]'
        file_name = re.sub(rstr, '_', file_name)  # 将标题中的特殊字符替换为下划线
        
        # 如果妙记来自会议，则将会议起止时间作为文件名的一部分
        if minutes['object_type'] == 0:
            start_time = time.strftime("%Y年%m月%d日%H时%M分", time.localtime(minutes['start_time'] / 1000))
            stop_time = time.strftime("%Y年%m月%d日%H时%M分", time.localtime(minutes['stop_time'] / 1000))
            file_name = start_time+"至"+stop_time+file_name
        else:
            create_time = time.strftime("%Y年%m月%d日%H时%M分", time.localtime(minutes['create_time'] / 1000))
            file_name = create_time+file_name
        
        return file_name

    def download_minutes(self, minutes_list):
        """
        下载妙记视频
        """
        logger.info("开始下载 %d 条妙记", len(minutes_list))
        
        # 检查保存路径权限
        if not os.path.exists(save_path):
            try:
                os.makedirs(save_path)
                logger.info(f"创建保存路径: {save_path}")
            except PermissionError:
                logger.error(f"无权限创建保存路径: {save_path}")
                return
        elif not os.access(save_path, os.W_OK):
            logger.error(f"无权限写入保存路径: {save_path}")
            return

        # 检查磁盘空间
        total, used, free = shutil.disk_usage(save_path)
        logger.info(f"磁盘总空间: {total // (2**30)}GB, 已用: {used // (2**30)}GB, 可用: {free // (2**30)}GB")
        if free < 1 * (2**30):  # 如果可用空间小于1GB
            logger.error("磁盘空间不足，无法下载")
            return

        with open('links.temp', 'w', encoding='utf-8') as f:
            for minutes in minutes_list:
                try:
                    video_url, file_name = self.get_minutes_url(minutes)
                    if video_url:
                        full_path = os.path.join(save_path, file_name)
                        os.makedirs(full_path, exist_ok=True)
                        f.write(f'{video_url}\n')
                        f.write(f'  dir={full_path}\n')
                        f.write(f'  out={file_name}.mp4\n')
                        logger.debug(f"写入下载链接: {video_url}, 保存路径: {full_path}")
                        self._save_downloaded_minutes(minutes['object_token'])
                except Exception as e:
                    logger.error("处理妙记时出错: %s", str(e))

        if not subtitle_only and os.path.getsize('links.temp') > 0:
            headers_option = ' '.join(f'--header="{k}: {v}"' for k, v in self.headers.items())
            proxy_cmd = f'--all-proxy={proxies["http"]}' if proxies else ""
            cmd = f'aria2c -c --input-file=links.temp {headers_option} --continue=true --auto-file-renaming=true --console-log-level=error --summary-interval=0 {proxy_cmd} -s16 -x16 -k1M'
            
            logger.debug("正在执行aria2c命令")
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
            
            if result.returncode != 0:
                logger.error(f"aria2c 命令执行失败: {result.stderr}")
            else:
                logger.debug("aria2c命令执行完毕")

            # 检查文件是否真的被下载
            for minutes in minutes_list:
                file_name = self._generate_file_name(minutes)
                expected_path = os.path.join(save_path, file_name, f"{file_name}.mp4")
                if os.path.exists(expected_path):
                    logger.info(f"文件已成功下载: {expected_path}")
                else:
                    logger.error(f"文件下载失败或未找到: {expected_path}")

        os.remove('links.temp')
        logger.info("临时文件 'links.temp' 已删除")

        for file_name, start_time in self.meeting_time_dict.items():
            try:
                self._update_file_timestamp(file_name, start_time)
            except OSError as e:
                logger.error("更新 %s 的创建时间时出错: %s", file_name, str(e))
        
        self.meeting_time_dict = {}

    def _update_file_timestamp(self, file_name, start_time):
        os.utime(os.path.join(save_path, file_name), (start_time, start_time))
        if not subtitle_only:
            os.utime(os.path.join(save_path, file_name, f"{file_name}.mp4"), (start_time, start_time))
        os.utime(os.path.join(save_path, file_name, f"{file_name}.{self.subtitle_type}"), (start_time, start_time))
        logger.debug("已更新 %s 的创建时间", file_name)

    def delete_minutes(self, num):
        """
        删除指定数量的最早几个妙记
        """
        logger.info("正在删除 %d 条最早的妙记", num)
        all_minutes = self.get_minutes()

        for index in tqdm(all_minutes[:num], desc='删除妙记'):
            try:
                self._delete_minute(index['object_token'])
                logger.debug("成功删除妙记: %s", index['object_token'])
            except Exception as e:
                logger.error(f"{e} 可能是没有该妙记的删除权限。")
                num += 1
                continue

    def _delete_minute(self, object_token):
        delete_url = 'https://meetings.feishu.cn/minutes/api/space/delete'
        params = {'object_tokens': object_token, 'is_destroyed': 'false', 'language': 'zh_cn'}
        resp = requests.post(url=delete_url, params=params, headers=self.headers, proxies=proxies)
        if resp.status_code != 200:
            raise Exception(f"删除妙记 http://meetings.feishu.cn/minutes/{object_token} 失败！{resp.json()}")

        params['is_destroyed'] = 'true'
        resp = requests.post(url=delete_url, params=params, headers=self.headers, proxies=proxies)
        if resp.status_code != 200:
            raise Exception(f"删除妙记 http://meetings.feishu.cn/minutes/{object_token} 失败！{resp.json()}")

if __name__ == '__main__':
    try:
        if not minutes_cookie:
            raise ValueError("cookie不能为空！")
        
        if not manager_cookie:
            while True:
                logger.info(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
                downloader = FeishuDownloader(minutes_cookie)
                if downloader.check_minutes():
                    downloader.delete_minutes(1)
                else:
                    logger.info("没有新的妙记需要处理")
                    logger.info(f"等待 {check_interval} 秒后再次检查...")
                    time.sleep(check_interval)
        else:
            x_csrf_token = manager_cookie[manager_cookie.find(' csrf_token=') + len(' csrf_token='):manager_cookie.find(';', manager_cookie.find(' csrf_token='))]
            if len(x_csrf_token) != 36:
                raise ValueError("manager_cookie中不包含csrf_token，请确保从请求`list?size=20&`中获取！")
            while True:
                logger.info(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
                downloader = FeishuDownloader(manager_cookie)
                if downloader.check_minutes():
                    downloader.delete_minutes(1)
                else:
                    logger.info("没有新的妙记需要处理")
                    logger.info(f"等待 {check_interval} 秒后再次检查...")
                    time.sleep(check_interval)
    except Exception as e:
        logger.exception("程序运行时发生错误: %s", str(e))