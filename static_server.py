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

# 基础配置
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public')
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'voice')

# 版本信息
VERSION = "1.72"
VERSION_INFO = {
    'version': VERSION,
    'release_date': '2024-02-11',
    'features': [
        '支持音频文件上传和播放',
        '域名白名单管理',
        '文件自动清理',
        '操作日志记录',
        '管理后台功能',
        '修复日志记录问题'
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
        self._load_admin_key()
        print(f"配置加载完成，管理员密钥: {self._admin_key}")
        
    def _load_admin_key(self):
        """从文件加载管理员密钥"""
        try:
            key_file = 'api_key.txt'
            print(f"尝试加载密钥文件: {key_file}")
            
            # 获取当前脚本的绝对路径
            current_dir = os.path.dirname(os.path.abspath(__file__))
            key_file_path = os.path.join(current_dir, key_file)
            print(f"密钥文件完整路径: {key_file_path}")
            
            if not os.path.exists(key_file_path):
                print(f"钥文件不存在: {key_file_path}")
                return
                
            with open(key_file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                print(f"读取到的文件内容: {content}")
                
                # 尝试解析内容
                if content:
                    if content.startswith('{'):
                        # JSON 格式
                        try:
                            data = json.loads(content)
                            key = data.get('admin_key')
                            if key:
                                print(f"从JSON成功加载管理员密钥: {key}")
                                self._admin_key = key
                                return
                        except json.JSONDecodeError:
                            print("JSON解析失败")
                    else:
                        # 普通文本格式
                        lines = content.split('\n')
                        for line in lines:
                            if 'admin_key' in line:
                                key = line.split(':')[1].strip().strip('"').strip("'")
                                print(f"从文本成功加载管理员密钥: {key}")
                                self._admin_key = key
                                return
                                
                print("未找到有效的管理员密钥")
                
        except Exception as e:
            print(f"加载管理员密钥时出错: {e}")
            print(traceback.format_exc())
            
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
                print("未提供来源")
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
            print(f"清理文件时出错: {e}")
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
    """错误处理装饰器"""
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
    VERSION = "1.72"
    SERVER_NAME = f"Audio Server v{VERSION}"
    
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
            
            if self.path == '/api/admin/whitelist':
                self.handle_whitelist_add()
            elif self.path == '/api/admin/verify':
                self.handle_admin_verify()
            elif self.path.startswith('/api/admin/play/'):
                self.handle_file_play()
            elif self.path == '/api/upload':
                self.handle_file_upload()
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"处理POST请求时出错: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_file_upload(self):
        """处理文件上传"""
        try:
            print("\n=== 处理文件上传 ===")
            
            # 验证请来源
            if not self.verify_origin():
                print("来源验证失败")
                self.send_json_error(403, "Origin not allowed")
                return
                
            # 验证Content-Type
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                print(f"Content-Type 不正确: {content_type}")
                self.send_json_error(400, "Invalid Content-Type")
                return
                
            # 解析文件数据
            try:
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': self.headers['Content-Type'],
                    }
                )
            except Exception as e:
                print(f"解析表单数据失败: {e}")
                self.send_json_error(400, "Failed to parse form data")
                return
            
            # 检查是否有文件
            if 'file' not in form:
                print("未找到文件")
                self.send_json_error(400, "No file uploaded")
                return
                
            # 获取文件信息
            file_item = form['file']
            if not file_item.filename:
                print("文件名为空")
                self.send_json_error(400, "No file selected")
                return
                
            # 获取原始文件名
            original_filename = os.path.basename(file_item.filename)
            print(f"原始文件名: {original_filename}")
            
            # 生成安全的文件名
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_filename = f"{timestamp}_{original_filename}"
            filepath = os.path.join('voice', safe_filename)
            
            # 确保目录存在
            os.makedirs('voice', exist_ok=True)
            
            # 保存文件
            try:
                with open(filepath, 'wb') as f:
                    f.write(file_item.file.read())
            except Exception as e:
                print(f"保存文件失败: {e}")
                self.send_json_error(500, "Failed to save file")
                return
                
            file_size = os.path.getsize(filepath)
            print(f"文件已保存: {filepath} ({file_size} bytes)")
            
            # 添加到数据库
            try:
                file_data = {
                    'filename': safe_filename,
                    'original_filename': original_filename,
                    'file_size': file_size,
                    'file_path': filepath,
                    'uploader_ip': self.client_address[0],
                    'mime_type': file_item.type,
                    'extra_info': {
                        'user_agent': self.headers.get('User-Agent'),
                        'content_length': self.headers.get('Content-Length'),
                        'request_time': time.time()
                    }
                }
                
                self.db_manager.add_audio_file(file_data)
                print("文件信息已保存到数据库")
            except Exception as e:
                print(f"保存到数据库失: {e}")
                # 除已上传的文件
                os.remove(filepath)
                self.send_json_error(500, "Failed to save file information")
                return
            
            # 发送成功响应
            self.send_json_response({
                'code': 200,
                'message': '上传成功',
                'data': {
                    'filename': safe_filename,
                    'file_url': f'/voice/{safe_filename}'
                }
            })
            print("上传处理完成")
            
        except Exception as e:
            print(f"上传处理出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def send_json_response(self, data):
        """发送JSON响应"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')  # 允许跨域
        self.send_header('Access-Control-Allow-Headers', 'X-Admin-Key')  # 许自定义头
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_json_error(self, code, message):
        """发送JSON错误响应"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'X-Admin-Key')
        self.end_headers()
        error_data = {
            'code': code,
            'message': message
        }
        self.wfile.write(json.dumps(error_data).encode())

    def handle_admin_verify(self):
        """处理管理员验证请求"""
        try:
            print("\n=== 验证管理钥 ===")
            provided_key = self.headers.get('X-Admin-Key')
            
            print(f"收到验证请求:")
            print(f"- Header中的密钥: {provided_key}")
            
            # 如果header中没有密钥，尝试请求体获取
            if not provided_key and int(self.headers.get('Content-Length', 0)) > 0:
                content_length = int(self.headers.get('Content-Length'))
                post_data = self.rfile.read(content_length)
                try:
                    body = json.loads(post_data.decode('utf-8'))
                    provided_key = body.get('key')
                    print(f"- 请求体中的密钥: {provided_key}")
                except:
                    print("解析请求体失败")
            
            if not provided_key:
                print("未提供密钥")
                self.send_json_error(401, "No admin key provided")
                return
                
            if self.config_manager.verify_admin_key(provided_key):
                print("验证成功")
                self.send_json_response({
                    'code': 200,
                    'message': 'Verification successful'
                })
            else:
                print("验证失败")
                self.send_json_error(401, "Invalid admin key")
                
        except Exception as e:
            print(f"验证管理员密钥时出错: {e}")
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
            
            print(f"请求来源: {request_source}")
            
            if not request_source:
                print("无法获取请求来源")
                return False
                
            # 解析域名，去除端口号
            parsed_url = urlparse(request_source)
            request_domain = parsed_url.netloc.split(':')[0]  # 只取域名部分，去除端口
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
                
                # 验证结果
                is_allowed = request_domain in allowed_domains
                print(f"验证结果: {'允许' if is_allowed else '禁止'}")
                
                return is_allowed
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"验证请求来源时出错: {e}")
            print(traceback.format_exc())
            return False

    def do_GET(self):
        """处理GET请求"""
        try:
            print(f"\n=== 处理GET请求 ===")
            print(f"请求路径: {self.path}")
            
            # 解析URL
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            # 路由处理
            if path.startswith('/voice/'):
                filename = os.path.basename(path)
                try:
                    self.serve_audio_file(filename)
                except Exception as e:
                    print(f"处理音频文件时出错: {e}")
                    try:
                        error_message = str(e).encode('utf-8', errors='ignore').decode('utf-8')
                        self.send_error(500, error_message)
                    except:
                        self.send_error(500, "Internal Server Error")
            elif path == '/':
                self.serve_file('public/index.html', 'text/html')
            elif path == '/admin':
                self.serve_file('public/admin.html', 'text/html')
            elif path == '/api/admin/files':
                self.handle_admin_files_query()
            elif path.startswith('/api/admin/file/'):
                self.handle_file_details()
            elif path == '/api/admin/whitelist':
                self.handle_whitelist_query()
            elif path == '/api/admin/logs':
                self.handle_logs_query()
            elif path == '/api/admin/logs/export':
                self.handle_logs_export()
            else:
                self.send_error(404, "File not found")
                
        except Exception as e:
            print(f"处理GET请求时出错: {e}")
            try:
                error_message = str(e).encode('utf-8', errors='ignore').decode('utf-8')
                self.send_error(500, error_message)
            except:
                self.send_error(500, "Internal Server Error")

    def serve_file(self, filepath, content_type):
        """服务静态文件"""
        try:
            # 确保文件路径安全
            filepath = os.path.abspath(filepath)
            if not os.path.exists(filepath):
                print(f"件不存在: {filepath}")
                self.send_error(404, "File not found")
                return
                
            # 读取文件内容
            with open(filepath, 'rb') as f:
                content = f.read()
                
            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            print(f"服务文件时出错: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def get_content_type(self, filepath):
        """获取文件的Content-Type"""
        ext = os.path.splitext(filepath)[1].lower()
        content_types = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.mp3': 'audio/mpeg',
            '.wav': 'audio/wav',
            '.ogg': 'audio/ogg',
        }
        return content_types.get(ext, 'application/octet-stream')

    def handle_admin_uploads(self):
        """处理管理员上传表请求"""
        try:
            print("\n=== 处理理员上传列表请求 ===")
            if not self.verify_admin():
                self.send_error(401, "Invalid admin key")
                return
                
            # 获取文件列表
            files = []
            if os.path.exists('uploads.json'):
                with open('uploads.json', 'r', encoding='utf-8') as f:
                    files = json.load(f)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                'code': 200,
                'data': files
            }
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            print(f"处理理员上传列表请求失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_audio_file(self):
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

    def handle_delete_file(self):
        """处理文件删除请求"""
        try:
            # 验管理员密钥
            admin_key = self.headers.get('X-Admin-Key')
            if not self.config_manager.verify_admin_key(admin_key):
                self.send_error(401, 'Invalid admin key')
                return

            # 获取文件名
            file_name = os.path.basename(self.path)
            file_path = os.path.join(UPLOAD_DIR, file_name)
            
            print(f"尝试删除文件: {file_path}")
            
            if os.path.exists(file_path):
                # 删除文件
                os.remove(file_path)
                
                # 更新记录文件
                if os.path.exists('upload_records.txt'):
                    with open('upload_records.txt', 'r', encoding='utf-8') as f:
                        records = [json.loads(line) for line in f if line.strip()]
                    
                    # 过滤掉被删除的文件记录
                    records = [r for r in records if r.get('filename') != file_name]
                    
                    with open('upload_records.txt', 'w', encoding='utf-8') as f:
                        for record in records:
                            f.write(json.dumps(record, ensure_ascii=False) + '\n')
                
                # 发送成功响应
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                response = {
                    'code': 200,
                    'message': '文件删除成功'
                }
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))
                print(f"文件删除成功: {file_path}")
            else:
                print(f"要除的文件不存在: {file_path}")
                self.send_error(404, "File not found")
        except Exception as e:
            print(f"删除文件失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_domain_management(self):
        """处理域名管理请求"""
        try:
            # 验证管理员密钥
            admin_key = self.headers.get('X-Admin-Key')
            if not self.config_manager.verify_admin_key(admin_key):
                self.send_error(401, 'Invalid admin key')
                return

            # 获取请求数据
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            action = data.get('action')
            
            # 理列表请求
            if action == 'list':
                response = {
                    'allowed_origins': list(self.config_manager.allowed_origins),
                    'domain_patterns': [p.pattern for p in self.config_manager.domain_patterns]
                }
            # 处理加请求
            elif action == 'add':
                origin = data.get('origin')
                is_pattern = data.get('is_pattern', False)
                success = self.config_manager.add_origin(origin, is_pattern)
                response = {
                    'success': success,
                    'allowed_origins': list(self.config_manager.allowed_origins),
                    'domain_patterns': [p.pattern for p in self.config_manager.domain_patterns]
                }
            # 处理删除请求
            elif action == 'remove':
                origin = data.get('origin')
                is_pattern = data.get('is_pattern', False)
                success = self.config_manager.remove_origin(origin, is_pattern)
                response = {
                    'success': success,
                    'allowed_origins': list(self.config_manager.allowed_origins),
                    'domain_patterns': [p.pattern for p in self.config_manager.domain_patterns]
                }
            else:
                self.send_error(400, 'Invalid action')
                return

            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))

        except Exception as e:
            print(f"处理域名管理请求失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def do_DELETE(self):
        """处理DELETE请求"""
        try:
            print(f"\n=== 处理DELETE请求 ===")
            print(f"请求路径: {self.path}")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 解析URL
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            # 处理白名单删除
            if path.startswith('/api/admin/whitelist/'):
                whitelist_id = path.split('/')[-1]
                try:
                    whitelist_id = int(whitelist_id)
                    self.handle_whitelist_delete(whitelist_id)
                except ValueError:
                    print(f"无效的白名单ID: {whitelist_id}")
                    self.send_json_error(400, "Invalid whitelist ID")
            # 处理文件删除
            elif path.startswith('/api/admin/delete/'):
                filename = path.split('/')[-1]
                self.handle_file_delete(filename)
            else:
                print(f"未知的DELETE请求路径: {path}")
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"处理DELETE请求时出错: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_file_delete(self, filename):
        """处理文件删除请求"""
        try:
            print(f"\n=== 处理文件删除: {filename} ===")
            
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 检查文件是否存在
                cursor.execute("""
                    SELECT id, filename, original_filename, is_deleted
                    FROM audio_files
                    WHERE filename = ?
                """, (filename,))
                
                file_info = cursor.fetchone()
                if not file_info:
                    print(f"文件不存在: {filename}")
                    self.send_json_error(404, "文件��存在")
                    return
                    
                file_id, filename, original_filename, is_deleted = file_info
                
                if is_deleted:
                    print(f"文件已被删除: {filename}")
                    self.send_json_error(400, "文件已被删除")
                    return
                    
                # 物理文件路径
                file_path = os.path.join('voice', filename)
                
                # 删除物理文件
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"物理文件删除成功: {file_path}")
                else:
                    print(f"物理文件不存在: {file_path}")
                
                # 更新数据库记录
                cursor.execute("""
                    UPDATE audio_files
                    SET is_deleted = 1,
                        delete_time = datetime('now')
                    WHERE id = ?
                """, (file_id,))
                
                # 记录删除操作
                cursor.execute("""
                    INSERT INTO operation_logs (
                        operation_type,
                        operator_ip,
                        file_id,
                        details,
                        operation_time
                    ) VALUES (?, ?, ?, ?, datetime('now'))
                """, (
                    'delete',
                    self.client_address[0],
                    file_id,
                    json.dumps({
                        'filename': filename,
                        'original_filename': original_filename
                    })
                ))
                
                conn.commit()
                print(f"文件删除成功: {filename}")
                
                self.send_json_response({
                    'code': 200,
                    'message': '删除成功',
                    'data': {
                        'filename': filename,
                        'original_filename': original_filename
                    }
                })
                
            except sqlite3.Error as e:
                print(f"数据库操作错误: {e}")
                conn.rollback()
                self.send_json_error(500, f"数据库错误: {str(e)}")
            finally:
                conn.close()
                
        except Exception as e:
            print(f"删除文件时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_whitelist_delete(self, whitelist_id):
        """处理删除白名单请求"""
        try:
            print(f"\n=== 处理删除白名单 {whitelist_id} ===")
            
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
                    
                domain = existing[0]
                print(f"准备删除域名: {domain}")
                
                # 删除记录
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
                        'domain': domain
                    }),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                
                conn.commit()
                print(f"白名单删除成功: {domain}")
                
                self.send_json_response({
                    'code': 200,
                    'message': '删除成功',
                    'data': {
                        'id': whitelist_id,
                        'domain': domain
                    }
                })
                
            except sqlite3.Error as e:
                print(f"数据库操作错误: {e}")
                conn.rollback()
                self.send_json_error(500, f"数据库错误: {str(e)}")
            finally:
                conn.close()
                
        except Exception as e:
            print(f"删除白名单时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_file_play(self):
        """处理文件播放请求"""
        try:
            print("\n=== 处理文件播放 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
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
                
                # 记录播放操作
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

    def serve_audio_file(self, filename):
        """服务音频文件"""
        try:
            print(f"\n=== 服务音频文件: {filename} ===")
            
            # 检查文件是否存在
            file_path = os.path.join('voice', filename)
            if not os.path.exists(file_path):
                print(f"文件不存在: {file_path}")
                self.send_error(404, "File not found")
                return
                
            # 获取文件大小
            file_size = os.path.getsize(file_path)
            
            # 设置响应头
            self.send_response(200)
            self.send_header('Content-Type', 'audio/mpeg')
            self.send_header('Content-Length', str(file_size))
            self.send_header('Accept-Ranges', 'bytes')
            self.end_headers()
            
            # 读取并发送文件内容
            with open(file_path, 'rb') as f:
                chunk_size = 8192  # 8KB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except (ConnectionAbortedError, BrokenPipeError):
                        print("客户端连接中断")
                        return
                    except Exception as e:
                        print(f"发送数据时出错: {e}")
                        return
                    
            print(f"文件发送成功: {filename}")
            
        except Exception as e:
            print(f"服务音频文件时出错: {e}")
            error_msg = "Internal Server Error"
            try:
                self.send_error(500, error_msg)
            except:
                pass

    def do_OPTIONS(self):
        """处理OPTIONS请求（用于CORS预检）"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Admin-Key')
        self.end_headers()

    def handle_logs_query(self):
        """处理日志查询请求"""
        try:
            print("\n=== 处理日志查询 ===")
            
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
                print("CSV文件发送成功")
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"导出日志时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_admin_files_query(self):
        """处理管理员文件查询请求"""
        try:
            print("\n=== 处理管理员文件查询 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 解析查询参数
            parsed_url = urlparse(self.path)
            params = parse_qs(parsed_url.query)
            
            filename = params.get('filename', [''])[0]
            status = params.get('status', [''])[0]
            start_date = params.get('start_date', [''])[0]
            end_date = params.get('end_date', [''])[0]
            
            # 构建查询条件
            conditions = []
            query_params = []
            
            if filename:
                conditions.append("filename LIKE ?")
                query_params.append(f"%{filename}%")
                
            if status:
                conditions.append("status = ?")
                query_params.append(status)
                
            if start_date:
                conditions.append("upload_time >= ?")
                query_params.append(f"{start_date} 00:00:00")
                
            if end_date:
                conditions.append("upload_time <= ?")
                query_params.append(f"{end_date} 23:59:59")
                
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                cursor.execute(f"""
                    SELECT 
                        id,
                        filename,
                        original_filename,
                        file_size,
                        upload_time,
                        status,
                        is_deleted,
                        delete_time,
                        uploader_ip
                    FROM audio_files
                    WHERE {where_clause}
                    ORDER BY upload_time DESC
                """, query_params)
                
                columns = [desc[0] for desc in cursor.description]
                files = [dict(zip(columns, row)) for row in cursor.fetchall()]
                
                self.send_json_response({
                    'code': 200,
                    'message': 'success',
                    'data': files
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"查询文件时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

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
                    
                # 添加白名单记录
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
            print("\n=== 处理白名单查询 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
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
            print(f"\n=== 处理更新白名单 {whitelist_id} ===")
            
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
            
            print(f"更新白名单: id={whitelist_id}, status={status}, description={description}")
            
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 检查记录是否存在
                cursor.execute("SELECT domain FROM whitelist WHERE id = ?", (whitelist_id,))
                existing = cursor.fetchone()
                
                if not existing:
                    print(f"白名单记录不存在: {whitelist_id}")
                    self.send_json_error(404, "记不存在")
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
                    'message': '更新成功',
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
                    
                # 删除记录
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

class Logger:
    def __init__(self, log_dir='logs'):
        """初始化日志管理器"""
        print("\n=== 初始化日志管理器 ===")
        # 确保日志目录存在
        self.log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_dir)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            print(f"创建日志目录: {self.log_dir}")
            
        # 设置日志文件路径
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
        print("\n=== 初始化数据库管理器 ===")
        self.db_file = 'audio_server.db'
        self.init_database()
        
    def init_database(self):
        """初始化数据库"""
        try:
            print("\n=== 初始化数据库 ===")
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            # 创建音频文件表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audio_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL UNIQUE,
                original_filename TEXT,
                file_size INTEGER,
                upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                is_deleted INTEGER DEFAULT 0,
                delete_time DATETIME,
                uploader_ip TEXT
            )
            """)
            
            # 创建操作日志表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS operation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                operation_type TEXT NOT NULL,
                operation_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                operator_ip TEXT,
                details TEXT,
                FOREIGN KEY (file_id) REFERENCES audio_files(id)
            )
            """)
            
            # 创建白名单表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                description TEXT,
                status INTEGER DEFAULT 1,
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                update_time DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """)
            
            # 插入默认域名
            cursor.execute("""
            INSERT OR IGNORE INTO whitelist (domain, description)
            VALUES 
                ('localhost', '本地开发环境'),
                ('127.0.0.1', '本地IP地址')
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"初始化数据库时出错: {e}")
            print(traceback.format_exc())
        finally:
            conn.close()
    
    def add_audio_file(self, file_data):
        """添加音频文记录"""
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
        """标记文件为已删除"""
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

# 初始化新数据库
db_manager = DatabaseManager()
db_manager.init_database()
