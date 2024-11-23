from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import json
from datetime import datetime
import cgi
import traceback
import re
from urllib.parse import parse_qs
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import sqlite3
import logging
import io
import csv
import uuid

# 基础配置
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public')
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'voice')

# 版本信息
VERSION = "1.98"
VERSION_INFO = {
    'version': VERSION,
    'release_date': '2024-03-19',
    'features': [
        '支持音频文件上传和播放',
        '域名白名单管理',
        '文件自动清理',
        '操作日志记录',
        '管理后台功能',
        '优化白名单匹配规则',
        '支持子域名和子路径',
        '优化程序退出处理',
        '修复音频上传404问题',
        '修复重定向循环问题',
        '优化路由处理逻辑',
        '优化网页访问体验',
        '修复路由匹配问',
        '添加详细日志输出',
        '优化文件上传处理',
        '优化响应头处理',
        '简化上传路径',
        '优化Nginx配置',
        '优化路由处理机制',
        '修复文件保存功能',
        '修复数据库结构',
        '优化管理员验证',
        '修复音频文件访问',
        '修复管理员验证配置',
        '优化音频文件路由',
        '优化主页路由匹配',
        '优化页面布局和样式'
    ]
}

def print_version_info():
    """打印版本信息"""
    print("\n=== 音频文件服务器 V{} ===".format(VERSION))
    print(f"发布日期: {VERSION_INFO['release_date']}")
    print("\n主要功能:")
    for feature in VERSION_INFO['features']:
        print(f"- {feature}")
    print("="*30 + "\n")

class ConfigManager:
    _instance = None
    _admin_key = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance
        
    def _load_config(self):
        """加载配置"""
        print("\n=== 初始化配置管理器 ===")
        self.config = {
            'allowed_origins': ['localhost', '127.0.0.1'],
            'upload_dir': 'voice',
            'max_file_size': 100 * 1024 * 1024  # 100MB
        }
        # 直接设置管理员密钥
        self._admin_key = 'dgp432126'
        print(f"配置加载完成，管理员密钥: {self._admin_key}")

    @property
    def admin_key(self):
        """获取管理员密钥"""
        return self._admin_key

    def verify_admin_key(self, provided_key):
        """验证管理员密钥"""
        try:
            if not self._admin_key:
                print("未配置管理员密钥")
                return False
                
            print(f"验证密钥:")
            print(f"- 提供的密钥: {provided_key}")
            print(f"- 正确的密钥: {self._admin_key}")
            
            result = provided_key == self._admin_key
            print(f"证结果: {'成功' if result else '失败'}")
            return result
            
        except Exception as e:
            print(f"验证密钥时出错: {e}")
            print(traceback.format_exc())
            return False

    def is_origin_allowed(self, origin):
        """检查来源是否允许"""
        try:
            print(f"\n=== 验证请求来源 ===")
            print(f"请求来源: {origin}")
            
            if not origin:
                print("未提来源")
                return False
                
            try:
                parsed_origin = urlparse(origin)
                hostname = parsed_origin.hostname
                print(f"解析的主机名: {hostname}")
                
                # 检查是否在允许列表中
                is_allowed = hostname in self.config['allowed_origins']
                print(f"允许的域名: {self.config['allowed_origins']}")
                print(f"验证结果: {'允许' if is_allowed else '禁止'}")
                return is_allowed
                
            except Exception as e:
                print(f"解析来源时出错: {e}")
                return False
                
        except Exception as e:
            print(f"验证来源时出错: {e}")
            print(traceback.format_exc())
            return False
            
    def get_upload_dir(self):
        """获取上传目录"""
        return self.config['upload_dir']
        
    def get_max_file_size(self):
        """获取最大文件大小"""
        return self.config['max_file_size']

class FileCleanupThread(threading.Thread):
    """文件清理线程"""
    def __init__(self, upload_dir, logger):
        super().__init__()
        self.upload_dir = upload_dir
        self.logger = logger
        self.interval = 300  # 设置固定的清理间隔为300秒（5分钟）
        self.daemon = True
        print(f"初始化文件清线程 - 间隔: {self.interval}秒")

    def run(self):
        """运行清理线程"""
        while True:
            try:
                print("\n=== 开始清理过期文件 ===")
                self.cleanup_files()
                time.sleep(self.interval)  # 使用整数间隔
            except Exception as e:
                print(f"清理文件时出错: {e}")
                print(traceback.format_exc())
                time.sleep(300)  # 发生错误时等待5分钟
    
    def cleanup_files(self):
        """清理过期文件"""
        try:
            now = datetime.now()
            expiry_time = now - timedelta(hours=1)
            cleaned_count = 0
            cleaned_size = 0
            
            for filename in os.listdir(self.upload_dir):
                file_path = os.path.join(self.upload_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                
                if file_time < expiry_time:
                    file_size = os.path.getsize(file_path)
                    os.remove(file_path)
                    cleaned_count += 1
                    cleaned_size += file_size
                    
                    # 记录自动清理日志
                    self.logger.log('auto_delete', {
                        'filename': filename,
                        'size': file_size,
                        'age': str(now - file_time),
                        'reason': 'expired'
                    })
            
            if cleaned_count > 0:
                self.logger.log('cleanup_summary', {
                    'cleaned_files': cleaned_count,
                    'cleaned_size': cleaned_size,
                    'expiry_hours': 1
                })
                
        except Exception as e:
            print(f"理文件时出错: {e}")
            print(traceback.format_exc())
            self.logger.log('cleanup_error', {
                'error': str(e)
            })

def formatSize(size):
    """格式化件小"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"

def handle_errors(func):
    """错"""
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            print(f"{func.__name__} 出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))
    return wrapper

class CustomHandler(BaseHTTPRequestHandler):
    """HTTP请求处理器"""
    VERSION = "1.98"
    SERVER_NAME = f"Audio Server v{VERSION}"
    ADMIN_KEY = "dgp432126"  # 直接定义为类变量
    
    config_manager = ConfigManager()
    logger = None
    db_manager = None
    
    @classmethod
    def initialize(cls):
        """初始化处理器的静态组件"""
        print("\n=== 初始化处理器组件 ===")
        cls.logger = Logger()
        cls.db_manager = DatabaseManager()
        print("静态组件初始化完成")

    def __init__(self, *args, **kwargs):
        """实例初始化"""
        if not self.config_manager:
            self.initialize()
        super().__init__(*args, **kwargs)

    @handle_errors
    def do_POST(self):
        """处理POST请求"""
        try:
            print(f"\n=== 处理POST请求 ===")
            print(f"请求路径: {self.path}")
            print(f"请求头: {self.headers}")
            print(f"请求方法: {self.command}")
            
            # 规范化路径
            path = self.path.rstrip('/')
            if path.startswith('/audio'):
                path = path[6:]  # 移除 /audio 前缀
            
            print(f"处理后的路径: {path}")
            
            # 处理路径
            if path in ['/api/upload', '/upload']:
                print(f"匹配到文件上传API路由")
                self.handle_file_upload()
            elif path in ['/api/admin/verify']:
                print(f"匹配到管理员验证API路由")
                self.handle_admin_verify()
            elif path.startswith('/api/admin/play/'):
                print(f"匹配到音频播放API路由")
                self.handle_file_play()
            else:
                print(f"未找到匹配的路由: {path}")
                print(f"原始路径: {self.path}")
                print(f"当前支持的POST路由:")
                print("- /api/upload")
                print("- /upload")
                print("- /api/admin/verify")
                print("- /api/admin/play/*")
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"处理POST请求时出错: {e}")
            print(f"错误类型: {type(e)}")
            print(f"错误堆栈:")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_file_upload(self):
        """处理文件上传"""
        try:
            print("\n=== 处理文件上传 ===")
            print(f"完整请求路径: {self.path}")
            print(f"请求方法: {self.command}")
            print(f"请求头信息:")
            for header, value in self.headers.items():
                print(f"  {header}: {value}")
            
            # 验证 Content-Type
            content_type = self.headers.get('Content-Type', '')
            print(f"Content-Type: {content_type}")
            if not content_type.startswith('multipart/form-data'):
                print("错误: Content-Type 不是 multipart/form-data")
                self.send_json_error(400, "Invalid Content-Type")
                return
            
            # 获取请求体大小
            content_length = int(self.headers.get('Content-Length', 0))
            print(f"上传文件大小: {content_length} 字节")
            
            # 解析表单数据
            print("开始解析表单数据...")
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type,
                    'CONTENT_LENGTH': str(content_length)
                }
            )
            
            print(f"表单字段列表: {list(form.keys())}")
            
            # 检查文件字段
            if 'file' not in form:
                print("错误: 表单中没有找到文件字段")
                self.send_json_error(400, "No file field in form")
                return
            
            file_item = form['file']
            print(f"文件信息:")
            print(f"  - 原始文件名: {file_item.filename}")
            print(f"  - 文件类型: {file_item.type}")
            print(f"  - 文件大小: {len(file_item.value)} 字节")
            
            # 保存文件
            try:
                filename = self.save_uploaded_file(file_item)
                print(f"文件保存成功: {filename}")
                
                # 返回成功响应
                response_data = {
                    'status': 'success',
                    'message': 'File uploaded successfully',
                    'filename': filename
                }
                print(f"回响应: {response_data}")
                self.send_json_response(response_data)
                
            except Exception as e:
                print(f"保存文件时出错: {e}")
                print(traceback.format_exc())
                self.send_json_error(500, f"Failed to save file: {str(e)}")
                
        except Exception as e:
            print(f"处理上传请求时出错: {e}")
            print(f"错误类型: {type(e)}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def send_json_response(self, data):
        """发送JSON响应"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_json_error(self, status_code, message):
        """发送JSON错误响应"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({
            'status': 'error',
            'message': message
        }).encode())

    def handle_admin_verify(self):
        """处理管理员验证"""
        try:
            print("\n=== 处理管理员验证 ===")
            print(f"请求路径: {self.path}")
            
            # 读取请求数据
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            print(f"接收到的数据: {data}")
            
            # 获取密码并去除空白字符
            input_password = data.get('password', '').strip()
            config_manager = ConfigManager()
            correct_password = config_manager.admin_key  # 使用属性访问
            
            print(f"输入的密码: {input_password}")
            print(f"正确的密码: {correct_password}")
            
            # 验证密码
            if input_password and correct_password and input_password == correct_password:
                # 生成 token
                token = str(uuid.uuid4())
                
                # 返回成功响应
                response_data = {
                    'status': 'success',
                    'message': '验证成功',
                    'token': token
                }
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
                print("验证成功")
            else:
                # 返回失败响应
                response_data = {
                    'status': 'error',
                    'message': '密码错误'
                }
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
                print("验证失败")
                
        except Exception as e:
            print(f"验证处理失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def verify_admin(self):
        """验证管理员权限"""
        try:
            provided_key = self.headers.get('X-Admin-Key')
            if not provided_key:
                print("未提供管密钥")
                return False
                
            return self.config_manager.verify_admin_key(provided_key)
            
        except Exception as e:
            print(f"验证管理员权限时出错: {e}")
            return False

    def verify_origin(self):
        """验证请求来源"""
        try:
            print("\n=== 验证请求来源 ===")
            
            # 获取请求来源
            origin = self.headers.get('Origin')
            referer = self.headers.get('Referer')
            request_source = origin or referer
            
            print(f"请来源: {request_source}")
            
            if not request_source:
                print("无法获取请求来源")
                return False
                
            # 解析域名，只取主域名部分
            parsed_url = urlparse(request_source)
            request_domain = parsed_url.netloc.split(':')[0]  # 去除端号
            print(f"解析的域名: {request_domain}")
            
            # 从数据库获取白名单
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    SELECT domain 
                    FROM whitelist 
                    WHERE status = 1
                """)
                
                allowed_domains = [row[0] for row in cursor.fetchall()]
                print(f"允许的域名: {allowed_domains}")
                
                # 验证结果：只比较主域名部分
                is_allowed = any(
                    request_domain == domain or 
                    request_domain.endswith('.' + domain)
                    for domain in allowed_domains
                )
                print(f"验证结果: {'允许' if is_allowed else '禁止'}")
                
                return is_allowed
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"验请求来源时出错: {e}")
            print(traceback.format_exc())
            return False

    @handle_errors
    def do_GET(self):
        """处理GET请求"""
        try:
            print(f"\n=== 处理GET请求: {self.path} ===")
            
            # 规范化路径
            path = self.path.rstrip('/')
            
            # 路由匹配
            if path == '/audio/admin':
                self.serve_admin_page()
            elif path == '/audio/api/admin/files':
                self.handle_admin_files()
            elif path.startswith('/audio/voice/'):
                self.handle_voice_file()
            elif path == '/audio' or path == '/audio/':
                self.serve_index_page()
            elif path.startswith('/audio/static/'):
                self.serve_static_file()
            else:
                print(f"未找到匹配的路由: {path}")
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"处理GET请求失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def serve_index_page(self):
        """服务主页"""
        try:
            file_path = os.path.join('public', 'index.html')
            print(f"尝试加载主页: {file_path}")
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(content)
                print("主页加载成功")
            else:
                print(f"主页文件不存在: {file_path}")
                self.send_error(404, "Index page not found")
        except Exception as e:
            print(f"服务主页失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def serve_admin_page(self):
        """服务管理页面"""
        try:
            file_path = os.path.join('public', 'admin.html')
            print(f"尝试加载管理页面: {file_path}")
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(content)
                print("管理页面加载成功")
            else:
                print(f"管理页面文件不存在: {file_path}")
                self.send_error(404, "Admin page not found")
        except Exception as e:
            print(f"服务管理页面失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def serve_static_file(self):
        """服务静态文件"""
        try:
            # 从路径中提取文件路径
            file_path = self.path.replace('/audio/static/', '')
            
            # 构建完整的文件路径
            full_path = os.path.join('public', 'static', file_path)
            print(f"尝试访问静态文件: {full_path}")
            
            if os.path.exists(full_path) and os.path.isfile(full_path):
                # 获取文件类型
                content_type = {
                    '.css': 'text/css',
                    '.js': 'application/javascript',
                    '.ico': 'image/x-icon',
                    '.png': 'image/png',
                    '.jpg': 'image/jpeg',
                    '.gif': 'image/gif'
                }.get(os.path.splitext(full_path)[1], 'application/octet-stream')
                
                with open(full_path, 'rb') as f:
                    content = f.read()
                    
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', len(content))
                self.send_header('Cache-Control', 'public, max-age=31536000')
                self.end_headers()
                self.wfile.write(content)
                print(f"静态文件 {file_path} 加载成功")
            else:
                print(f"文件不存在: {full_path}")
                self.send_error(404, "File not found")
        except Exception as e:
            print(f"服务静态文件时出错: {e}")
            self.send_error(500, str(e))

    def handle_file_upload(self):
        """处理文件上传"""
        try:
            print("\n=== 处理文件上传 ===")
            print(f"完整请求路径: {self.path}")
            print(f"请求方法: {self.command}")
            print(f"请求头信息:")
            for header, value in self.headers.items():
                print(f"  {header}: {value}")
            
            # 验证 Content-Type
            content_type = self.headers.get('Content-Type', '')
            print(f"Content-Type: {content_type}")
            if not content_type.startswith('multipart/form-data'):
                print("错误: Content-Type 不是 multipart/form-data")
                self.send_json_error(400, "Invalid Content-Type")
                return
            
            # 获取请求体大小
            content_length = int(self.headers.get('Content-Length', 0))
            print(f"上传文件大小: {content_length} 字节")
            
            # 解析表单数据
            print("开始解析表单数据...")
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': content_type,
                    'CONTENT_LENGTH': str(content_length)
                }
            )
            
            print(f"表单字段列表: {list(form.keys())}")
            
            # 检查文件字段
            if 'file' not in form:
                print("错误: 表单中没有找到文件字段")
                self.send_json_error(400, "No file field in form")
                return
            
            file_item = form['file']
            print(f"文件信息:")
            print(f"  - 原始文件名: {file_item.filename}")
            print(f"  - 文件类型: {file_item.type}")
            print(f"  - 文件大小: {len(file_item.value)} 字节")
            
            # 保存文件
            try:
                filename = self.save_uploaded_file(file_item)
                print(f"文件保存成功: {filename}")
                
                # 返回成功响应
                response_data = {
                    'status': 'success',
                    'message': 'File uploaded successfully',
                    'filename': filename
                }
                print(f"回响应: {response_data}")
                self.send_json_response(response_data)
                
            except Exception as e:
                print(f"保存文件时出错: {e}")
                print(traceback.format_exc())
                self.send_json_error(500, f"Failed to save file: {str(e)}")
                
        except Exception as e:
            print(f"处理上传请求时出错: {e}")
            print(f"错误类型: {type(e)}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_admin_verify(self):
        """处理管理员验证"""
        try:
            print("\n=== 处理管理员验证 ===")
            print(f"请求路径: {self.path}")
            
            # 读取请求数据
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            print(f"接收到的数据: {data}")
            
            # 获取密码并去除空白字符
            input_password = data.get('password', '').strip()
            config_manager = ConfigManager()
            correct_password = config_manager.admin_key  # 使用属性访问
            
            print(f"输入的密码: {input_password}")
            print(f"正确的密码: {correct_password}")
            
            # 验证密码
            if input_password and correct_password and input_password == correct_password:
                # 生成 token
                token = str(uuid.uuid4())
                
                # 返回成功响应
                response_data = {
                    'status': 'success',
                    'message': '验证成功',
                    'token': token
                }
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
                print("验证成功")
            else:
                # 返回失败响应
                response_data = {
                    'status': 'error',
                    'message': '密码错误'
                }
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
                print("验证失败")
                
        except Exception as e:
            print(f"验证处理失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_file_play(self):
        """处理文件播放请"""
        try:
            print("\n=== 处理文件播放 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 获取文件名
            filename = self.path.split('/')[-1]
            print(f"播放文件: {filename}")
            
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 获取文件信息
                cursor.execute("""
                    SELECT id, filename, original_filename
                    FROM audio_files
                    WHERE filename = ? AND is_deleted = 0
                """, (filename,))
                
                file_info = cursor.fetchone()
                if not file_info:
                    print(f"文件不存在: {filename}")
                    self.send_json_error(404, "文件不存在")
                    return
                    
                file_id, filename, original_filename = file_info
                
                # 记录播操作
                cursor.execute("""
                    INSERT INTO operation_logs (
                        operation_type,
                        operator_ip,
                        file_id,
                        details,
                        operation_time
                    ) VALUES (?, ?, ?, ?, datetime('now'))
                """, (
                    'play',
                    self.client_address[0],
                    file_id,
                    json.dumps({
                        'filename': filename,
                        'original_filename': original_filename
                    }),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                
                conn.commit()
                print(f"记录播放操作成功: {filename}")
                
                self.send_json_response({
                    'code': 200,
                    'message': '播放请求成功',
                    'data': {
                        'filename': filename,
                        'original_filename': original_filename
                    }
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"记录文件播放时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_voice_file(self):
        """处理音频文件请求"""
        try:
            # 获取文件名
            file_name = os.path.basename(self.path[7:])  # 移除 '/voice/' 前缀
            file_path = os.path.join(UPLOAD_DIR, file_name)
            
            print(f"请求音频件: {file_path}")
            
            if os.path.exists(file_path) and os.path.isfile(file_path):
                # 允许所有域名访问
                with open(file_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'audio/mpeg')
                self.send_header('Content-Length', len(content))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(content)
                print(f"音频文件发送成功: {file_path}")
            else:
                print(f"音频文件不存在: {file_path}")
                self.send_error(404, "Audio file not found")
        except Exception as e:
            print(f"处理音频文件失败: {e}")
            self.send_error(500, str(e))

    def do_OPTIONS(self):
        """处理 OPTIONS 请求"""
        print("\n=== 处理 OPTIONS 请求 ===")
        print(f"请求路径: {self.path}")
        print(f"请求头: {self.headers}")
        
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def handle_logs_query(self):
        """处理日志查询请求"""
        try:
            print("\n=== 处理日志询 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 解析查询参数
            parsed_url = urlparse(self.path)
            params = parse_qs(parsed_url.query)
            
            page = int(params.get('page', ['1'])[0])
            log_type = params.get('type', ['all'])[0]
            start_date = params.get('start', [''])[0]
            end_date = params.get('end', [''])[0]
            
            # 构建查询条件
            conditions = []
            params = []
            
            if log_type != 'all':
                conditions.append("operation_type = ?")
                params.append(log_type)
                
            if start_date:
                conditions.append("operation_time >= ?")
                params.append(f"{start_date} 00:00:00")
                
            if end_date:
                conditions.append("operation_time <= ?")
                params.append(f"{end_date} 23:59:59")
                
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 获取总记录数
                cursor.execute(f"""
                    SELECT COUNT(*) 
                    FROM operation_logs 
                    WHERE {where_clause}
                """, params)
                total = cursor.fetchone()[0]
                
                # 获取分页数据
                offset = (page - 1) * 20
                cursor.execute(f"""
                    SELECT 
                        ol.operation_time,
                        ol.operation_type,
                        ol.operator_ip,
                        af.filename,
                        ol.details
                    FROM operation_logs ol
                    LEFT JOIN audio_files af ON ol.file_id = af.id
                    WHERE {where_clause}
                    ORDER BY ol.operation_time DESC
                    LIMIT 20 OFFSET ?
                """, params + [offset])
                
                columns = ['operation_time', 'operation_type', 'operator_ip', 'filename', 'details']
                logs = [dict(zip(columns, row)) for row in cursor.fetchall()]
                
                # 处理详情字段
                for log in logs:
                    if log['details']:
                        log['details'] = json.loads(log['details'])
                
                self.send_json_response({
                    'code': 200,
                    'message': 'success',
                    'data': logs,
                    'total': total
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"查询志时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_logs_export(self):
        """处理日志导出请求"""
        try:
            print("\n=== 处理日志导出 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 解析查询参数
            parsed_url = urlparse(self.path)
            params = parse_qs(parsed_url.query)
            
            log_type = params.get('type', ['all'])[0]
            start_date = params.get('start', [''])[0]
            end_date = params.get('end', [''])[0]
            
            print(f"导出参数: type={log_type}, start={start_date}, end={end_date}")
            
            # 构建查询条件
            conditions = []
            query_params = []
            
            if log_type != 'all':
                conditions.append("operation_type = ?")
                query_params.append(log_type)
                
            if start_date:
                conditions.append("operation_time >= ?")
                query_params.append(f"{start_date} 00:00:00")
                
            if end_date:
                conditions.append("operation_time <= ?")
                query_params.append(f"{end_date} 23:59:59")
                
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 查询日志数据
                query = f"""
                    SELECT 
                        ol.operation_time,
                        ol.operation_type,
                        ol.operator_ip,
                        af.filename,
                        ol.details
                    FROM operation_logs ol
                    LEFT JOIN audio_files af ON ol.file_id = af.id
                    WHERE {where_clause}
                    ORDER BY ol.operation_time DESC
                """
                print(f"执行查询: {query}")
                print(f"查询参数: {query_params}")
                
                cursor.execute(query, query_params)
                rows = cursor.fetchall()
                
                print(f"查询到 {len(rows)} 条记录")
                
                # 生成CSV内容
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['操作时间', '操作类型', '操作者IP', '文件名', '详情'])
                
                type_map = {
                    'upload': '上传',
                    'play': '播放',
                    'delete': '删除',
                    'whitelist_add': '添加白名单',
                    'whitelist_update': '更新白名单',
                    'whitelist_delete': '删除白名单'
                }
                
                for row in rows:
                    writer.writerow([
                        row[0],
                        type_map.get(row[1], row[1]),
                        row[2],
                        row[3] or '-',
                        row[4] or '-'
                    ])
                
                # 发送响应
                csv_data = output.getvalue().encode('utf-8-sig')
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv; charset=utf-8')
                self.send_header('Content-Disposition', 
                               f'attachment; filename=system_logs_{datetime.now().strftime("%Y%m%d")}.csv')
                self.send_header('Content-Length', len(csv_data))
                self.end_headers()
                
                self.wfile.write(csv_data)
                print("CSV文件发送功")
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"导出日志时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_admin_files(self):
        """处理管理员获取文件列表请求"""
        try:
            print("\n=== 处理管理员文件列表请求 ===")
            if not self.verify_admin():
                self.send_error(401, "未授权访问")
                return
            
            # 获取查询参数
            params = parse_qs(urlparse(self.path).query)
            filename = params.get('filename', [''])[0]
            
            # 获取文件列表
            files = []
            for file in os.listdir(UPLOAD_DIR):
                if not file.endswith('.mp3'):
                    continue
                
                file_path = os.path.join(UPLOAD_DIR, file)
                file_stat = os.stat(file_path)
                
                # 如果有搜索条件，进行过滤
                if filename and filename.lower() not in file.lower():
                    continue
                
                files.append({
                    'filename': file,
                    'upload_time': datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'file_size': file_stat.st_size,
                    'status': 'active'
                })
            
            # 按上传时间倒序排序
            files.sort(key=lambda x: x['upload_time'], reverse=True)
            
            self.send_json_response({
                'code': 200,
                'message': 'success',
                'data': files
            })
            
        except Exception as e:
            print(f"获取文件列表失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_file_delete(self, filename):
        """处理文件删除请求"""
        try:
            print(f"\n=== 处理文件删除请求: {filename} ===")
            if not self.verify_admin():
                self.send_error(401, "未授权访问")
                return
            
            file_path = os.path.join(UPLOAD_DIR, filename)
            if not os.path.exists(file_path):
                self.send_json_error(404, "文件不存在")
                return
            
            # 删除文件
            os.remove(file_path)
            
            self.send_json_response({
                'code': 200,
                'message': '文件删除成功'
            })
            
        except Exception as e:
            print(f"删除文件失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_whitelist_add(self):
        """处理添加白名单请求"""
        try:
            print("\n=== 处理添加白名单 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 获取请求数据
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            domain = data.get('domain', '').strip()
            description = data.get('description', '').strip()
            
            print(f"添加白名单: domain={domain}, description={description}")
            
            if not domain:
                print("域名不能为空")
                self.send_json_error(400, "Domain is required")
                return
                
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 检查域名是否已存在
                cursor.execute("SELECT id FROM whitelist WHERE domain = ?", (domain,))
                existing = cursor.fetchone()
                
                if existing:
                    print(f"域名已存在: {domain}")
                    self.send_json_error(400, "域名已存在")
                    return
                    
                # 添加名单记录
                cursor.execute("""
                    INSERT INTO whitelist (
                        domain, 
                        description,
                        status,
                        create_time,
                        update_time
                    ) VALUES (?, ?, 1, datetime('now'), datetime('now'))
                """, (domain, description))
                
                whitelist_id = cursor.lastrowid
                
                # 记录操作日志
                cursor.execute("""
                    INSERT INTO operation_logs (
                        operation_type,
                        operator_ip,
                        details,
                        operation_time
                    ) VALUES (?, ?, ?, datetime('now'))
                """, (
                    'whitelist_add',
                    self.client_address[0],
                    json.dumps({
                        'domain': domain,
                        'description': description,
                        'whitelist_id': whitelist_id
                    })
                ))
                
                conn.commit()
                print(f"白名单添加成功: {domain}")
                
                self.send_json_response({
                    'code': 200,
                    'message': '白名单添加成功',
                    'data': {
                        'id': whitelist_id,
                        'domain': domain,
                        'description': description,
                        'status': 1,
                        'create_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                })
                
            except sqlite3.IntegrityError as e:
                print(f"数据库完整性错误: {e}")
                self.send_json_error(400, "域名已存在")
            except Exception as e:
                print(f"添加白名单时出错: {e}")
                conn.rollback()
                raise
            finally:
                conn.close()
                
        except Exception as e:
            print(f"添加白名单时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_whitelist_query(self):
        """处理白名单查询请求"""
        try:
            print("\n=== 处理白名查询 ===")
            
            # 验管理员权限
            if not self.verify_admin():
                print("管理员验证失")
                self.send_json_error(401, "Unauthorized")
                return
                
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 查询所有白名单记录
                cursor.execute("""
                    SELECT 
                        id,
                        domain,
                        description,
                        status,
                        create_time,
                        update_time
                    FROM whitelist
                    ORDER BY create_time DESC
                """)
                
                columns = [desc[0] for desc in cursor.description]
                whitelist = [dict(zip(columns, row)) for row in cursor.fetchall()]
                
                print(f"查询到 {len(whitelist)} 条白名单记录")
                
                self.send_json_response({
                    'code': 200,
                    'message': 'success',
                    'data': whitelist
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"查询白名单时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_whitelist_update(self, whitelist_id):
        """处理更新白名单请求"""
        try:
            print(f"\n=== 处理新白名单 {whitelist_id} ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 获取请求数据
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            status = 1 if data.get('status') else 0
            description = data.get('description', '').strip()
            
            print(f"更新白名: id={whitelist_id}, status={status}, description={description}")
            
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 检查记录是否存在
                cursor.execute("SELECT domain FROM whitelist WHERE id = ?", (whitelist_id,))
                existing = cursor.fetchone()
                
                if not existing:
                    print(f"白名单记录不存在: {whitelist_id}")
                    self.send_json_error(404, "记录不存在")
                    return
                    
                # 更新记录
                cursor.execute("""
                    UPDATE whitelist 
                    SET status = ?,
                        description = ?,
                        update_time = datetime('now')
                    WHERE id = ?
                """, (status, description, whitelist_id))
                
                # 记录操作日志
                cursor.execute("""
                    INSERT INTO operation_logs (
                        operation_type,
                        operator_ip,
                        details,
                        operation_time
                    ) VALUES (?, ?, ?, datetime('now'))
                """, (
                    'whitelist_update',
                    self.client_address[0],
                    json.dumps({
                        'whitelist_id': whitelist_id,
                        'domain': existing[0],
                        'status': status,
                        'description': description
                    })
                ))
                
                conn.commit()
                print(f"白名单更新成功: {whitelist_id}")
                
                self.send_json_response({
                    'code': 200,
                    'message': '新成功',
                    'data': {
                        'id': whitelist_id,
                        'status': status,
                        'description': description,
                        'update_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"更新白名单时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_whitelist_delete(self, whitelist_id):
        """处理删除白名单请求"""
        try:
            print(f"\n=== 处理删除白名单 {whitelist_id} ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 检查记录是否存在
                cursor.execute("SELECT domain FROM whitelist WHERE id = ?", (whitelist_id,))
                existing = cursor.fetchone()
                
                if not existing:
                    print(f"白名单记录不存在: {whitelist_id}")
                    self.send_json_error(404, "记录不存在")
                    return
                    
                # 除记录
                cursor.execute("DELETE FROM whitelist WHERE id = ?", (whitelist_id,))
                
                # 记录操作日志
                cursor.execute("""
                    INSERT INTO operation_logs (
                        operation_type,
                        operator_ip,
                        details,
                        operation_time
                    ) VALUES (?, ?, ?, datetime('now'))
                """, (
                    'whitelist_delete',
                    self.client_address[0],
                    json.dumps({
                        'whitelist_id': whitelist_id,
                        'domain': existing[0]
                    })
                ))
                
                conn.commit()
                print(f"白名单删除成功: {whitelist_id}")
                
                self.send_json_response({
                    'code': 200,
                    'message': '删除成功'
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"删除白名单时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def save_uploaded_file(self, file_item):
        """保存上传的文件"""
        try:
            print("\n=== 保存上传文件 ===")
            
            # 生成安全的文件名
            original_filename = file_item.filename
            file_ext = os.path.splitext(original_filename)[1].lower()
            safe_filename = f"{int(time.time())}_{os.urandom(4).hex()}{file_ext}"
            
            print(f"原始文件名: {original_filename}")
            print(f"安全文件名: {safe_filename}")
            
            # 确保上传目录存在
            if not os.path.exists(UPLOAD_DIR):
                print(f"创建传目录: {UPLOAD_DIR}")
                os.makedirs(UPLOAD_DIR)
                
            # 完整的文件路径
            file_path = os.path.join(UPLOAD_DIR, safe_filename)
            print(f"保存路径: {file_path}")
            
            # 写入文件
            with open(file_path, 'wb') as f:
                f.write(file_item.value)
                
            print(f"文件大小: {os.path.getsize(file_path)} 字节")
            
            # 记录到数据库
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO audio_files (
                filename, original_filename, file_path,
                file_size, upload_time, uploader_ip, 
                mime_type, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                safe_filename,
                original_filename,
                file_path,
                os.path.getsize(file_path),
                datetime.now(),
                self.client_address[0],
                file_item.type,
                'active'
            ))
            
            conn.commit()
            conn.close()
            
            print("文件保存成功")
            return safe_filename
            
        except Exception as e:
            print(f"保存文件时出错: {e}")
            print(traceback.format_exc())
            raise

    def serve_favicon(self):
        """服务favicon.ico"""
        try:
            favicon_path = os.path.join('public', 'static', 'favicon.ico')
            if os.path.exists(favicon_path):
                with open(favicon_path, 'rb') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-Type', 'image/x-icon')
                self.send_header('Content-Length', len(content))
                self.send_header('Cache-Control', 'public, max-age=31536000')
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "Favicon not found")
        except Exception as e:
            print(f"服务favicon时出错: {e}")
            self.send_error(500, str(e))

class Logger:
    def __init__(self, log_dir='logs'):
        """初始化日志管理器"""
        print("\n=== 初始日志管理器 ===")
        # 确保日志目录存在
        self.log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_dir)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            print(f"创建日志目录: {self.log_dir}")
            
        # 设置日志文路径
        current_date = datetime.now().strftime('%Y%m%d')
        self.log_file = os.path.join(self.log_dir, f'server_{current_date}.log')
        print(f"日志文件: {self.log_file}")
        
        # 配置日志格式
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('AudioServer')
        print("日志理器初始化完成")

    def info(self, message):
        """记录信息日志"""
        self.logger.info(message)

    def error(self, message, exc_info=None):
        """记录错误日志"""
        if exc_info:
            self.logger.error(message, exc_info=True)
        else:
            self.logger.error(message)

    def debug(self, message):
        """记录调日志"""
        self.logger.debug(message)

    def warning(self, message):
        """记录警告日志"""
        self.logger.warning(message)

class DatabaseManager:
    def __init__(self):
        print("\n=== 初始化数据管理器 ===")
        self.db_file = 'audio_server.db'
        self.init_database()
        
    def init_database(self):
        """初始化数据库"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 创建音频文件表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS audio_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT,
                upload_time DATETIME NOT NULL,
                uploader_ip TEXT,
                play_count INTEGER DEFAULT 0,
                last_play_time DATETIME,
                status TEXT DEFAULT 'active'
            )
            ''')
            
            # 创建操作日志表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS operation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                operation_type TEXT NOT NULL,
                operation_time DATETIME NOT NULL,
                operator_ip TEXT,
                details TEXT,
                FOREIGN KEY (file_id) REFERENCES audio_files (id)
            )
            ''')
            
            conn.commit()
            conn.close()
            print("数据库初始化完成")
            
        except Exception as e:
            print(f"初始化数据库时出错: {e}")
            print(traceback.format_exc())
            raise
    
    def add_audio_file(self, file_data):
        """添音频文记录"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO audio_files (
                filename, original_filename, file_size, upload_time,
                uploader_ip, file_path, mime_type, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_data['filename'],
                file_data.get('original_filename'),
                file_data['file_size'],
                datetime.now(),
                file_data.get('uploader_ip'),
                file_data['file_path'],
                file_data.get('mime_type'),
                'active'
            ))
            
            file_id = cursor.lastrowid
            
            # 添加上传操作日志
            cursor.execute('''
            INSERT INTO operation_logs (
                file_id, operation_type, operation_time, operator_ip, details
            ) VALUES (?, ?, ?, ?, ?)
            ''', (
                file_id,
                'upload',
                datetime.now(),
                file_data.get('uploader_ip'),
                json.dumps(file_data.get('extra_info', {}))
            ))
            
            conn.commit()
            return file_id
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def mark_file_deleted(self, filename, delete_data):
        """标记文件为已删"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            # 更新文件状态
            cursor.execute('''
            UPDATE audio_files 
            SET is_deleted = TRUE, 
                delete_time = ?, 
                delete_by = ?,
                status = 'deleted'
            WHERE filename = ?
            ''', (
                datetime.now(),
                delete_data.get('delete_by'),
                filename
            ))
            
            if cursor.rowcount == 0:
                raise Exception("File not found")
                
            # 获取文件ID
            cursor.execute('SELECT id FROM audio_files WHERE filename = ?', (filename,))
            file_id = cursor.fetchone()[0]
            
            # 添加删除作日志
            cursor.execute('''
            INSERT INTO operation_logs (
                file_id, operation_type, operation_time, operator_ip, details
            ) VALUES (?, ?, ?, ?, ?)
            ''', (
                file_id,
                'delete',
                datetime.now(),
                delete_data.get('operator_ip'),
                json.dumps(delete_data.get('extra_info', {}))
            ))
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def get_file_list(self, include_deleted=False):
        """获取文件列表"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        query = '''
        SELECT 
            a.*, 
            (SELECT COUNT(*) FROM operation_logs WHERE file_id = a.id) as operation_count
        FROM audio_files a
        '''
        
        if not include_deleted:
            query += ' WHERE NOT is_deleted'
            
        query += ' ORDER BY upload_time DESC'
        
        cursor.execute(query)
        columns = [desc[0] for desc in cursor.description]
        files = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return files
    
    def get_file_operations(self, file_id):
        """获取文件的操作历史"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM operation_logs 
        WHERE file_id = ? 
        ORDER BY operation_time DESC
        ''', (file_id,))
        
        columns = [desc[0] for desc in cursor.description]
        operations = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return operations

def run_server(port=8000):
    """运行服务器"""
    try:
        # 预先��始化配置管理器
        config_manager = ConfigManager()
        print(f"服务器启动时的管理员密钥: {config_manager.admin_key}")
        
        # 预先初始化处理器组件
        CustomHandler.initialize()
        
        server_address = ('', port)
        httpd = HTTPServer(server_address, CustomHandler)
        print(f"\n=== 服务器启动在端口 {port} ===")
        httpd.serve_forever()
    except Exception as e:
        print(f"启动服务器时出错: {e}")
        print(traceback.format_exc())

def ensure_directories():
    """确保必要的目录存在"""
    directories = ['public', 'voice']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"创建目录: {directory}")

if __name__ == '__main__':
    try:
        ensure_directories()
        run_server()
    except Exception as e:
        print(f"启动服务器时出错: {e}")
        print(traceback.format_exc())

# 删除现有数据库
if os.path.exists('audio_server.db'):
    os.remove('audio_server.db')
    print("已删除旧数据库")

# 初始化数据库
db_manager = DatabaseManager()
db_manager.init_database()
