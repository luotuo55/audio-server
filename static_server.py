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

# 基础配置
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public')
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'voice')

# 版本信息
VERSION = "1.7"
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
                print(f"密钥文件不存在: {key_file_path}")
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
            print(f"验证结果: {'成功' if result else '失败'}")
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
    VERSION = "1.7"
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
            
            if self.path == '/api/admin/verify':
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
        self.send_header('Access-Control-Allow-Headers', 'X-Admin-Key')  # 允许自定义头
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
                print("未提供管理密钥")
                return False
                
            return self.config_manager.verify_admin_key(provided_key)
            
        except Exception as e:
            print(f"验证管理员权限时出错: {e}")
            return False

    def verify_origin(self):
        """验证请求来源"""
        try:
            if not hasattr(self, 'config_manager') or self.config_manager is None:
                print("配置管理器未初始化")
                return False
                
            origin = self.headers.get('Origin')
            if not origin:
                # 如果是直接访问（没有Origin头），允许本地求
                client_ip = self.client_address[0]
                print(f"直接问 - 客户端IP: {client_ip}")
                return client_ip in ['127.0.0.1', 'localhost']
                
            return self.config_manager.is_origin_allowed(origin)
            
        except Exception as e:
            print(f"验证来源时出错: {e}")
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
            if path == '/':
                self.serve_file('public/index.html', 'text/html')
            elif path == '/admin':
                self.serve_file('public/admin.html', 'text/html')
            elif path == '/api/admin/files':
                self.handle_admin_files_query()
            elif path.startswith('/api/admin/file/'):
                self.handle_file_details()
            elif path.startswith('/voice/'):
                filename = os.path.basename(path)
                self.serve_audio_file(filename)
            else:
                self.send_error(404, "File not found")
                
        except Exception as e:
            print(f"处理GET请求时出错: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

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
        """处理管理员上传列表请求"""
        try:
            print("\n=== 处理管理员上传列表请求 ===")
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
                print(f"要删除的文件不存在: {file_path}")
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
            
            # 处理列表请求
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
            
            if self.path.startswith('/api/admin/delete/'):
                self.handle_file_delete()
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"处理DELETE请求时出错: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def handle_file_delete(self):
        """处理文件删除请求"""
        try:
            print("\n=== 处理文件删除 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 获取文件名
            filename = os.path.basename(self.path)
            print(f"删除文件: {filename}")
            
            # 检查文件是否存在
            file_path = os.path.join('voice', filename)
            if not os.path.exists(file_path):
                print(f"物理文件不存在: {file_path}")
                self.send_json_error(404, "File not found")
                return
                
            # 连接数据库
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 获取文件ID
                cursor.execute("SELECT id FROM audio_files WHERE filename = ? AND status = 'active'", (filename,))
                file_record = cursor.fetchone()
                
                if not file_record:
                    print("数据库记录不存在或已删除")
                    self.send_json_error(404, "File not found or already deleted")
                    return
                    
                file_id = file_record[0]
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # 1. 删除物理文件
                try:
                    os.remove(file_path)
                    print(f"物理文件删除成功: {file_path}")
                    physical_delete_success = True
                except Exception as e:
                    print(f"物理文件删除失败: {e}")
                    physical_delete_success = False
                
                # 2. 更新数据库状态
                cursor.execute("""
                    UPDATE audio_files 
                    SET status = 'deleted', 
                        is_deleted = 1,
                        delete_time = ?
                    WHERE id = ?
                """, (current_time, file_id))
                
                # 3. 记录操作日志
                details = {
                    'filename': filename,
                    'physical_delete': physical_delete_success
                }
                
                cursor.execute("""
                    INSERT INTO operation_logs (
                        file_id,
                        operation_type,
                        operation_time,
                        operator_ip,
                        details
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    file_id,
                    'delete',
                    current_time,
                    self.client_address[0],
                    json.dumps(details)
                ))
                
                conn.commit()
                print("数据库更新成功")
                
                # 4. 返回响应
                response_message = 'File deleted successfully'
                if not physical_delete_success:
                    response_message += ' (database only)'
                    
                self.send_json_response({
                    'code': 200,
                    'message': response_message,
                    'data': {
                        'physical_delete': physical_delete_success
                    }
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"删除文件时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def handle_file_play(self):
        """处理文件播放记录"""
        try:
            print("\n=== 处理文件播放 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 获取文件名
            filename = os.path.basename(self.path)
            print(f"播放文件: {filename}")
            
            # 连接数据库
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 检查文件是否存在
                cursor.execute("SELECT id FROM audio_files WHERE filename = ? AND status = 'active'", (filename,))
                file_record = cursor.fetchone()
                
                if not file_record:
                    print("文件不存在或已删除")
                    self.send_json_error(404, "File not found or deleted")
                    return
                    
                # 记录操作日志
                cursor.execute("""
                    INSERT INTO operation_logs (
                        file_id,
                        operation_type,
                        operator_ip,
                        details
                    ) VALUES (?, 'play', ?, ?)
                """, (
                    file_record[0],
                    self.client_address[0],
                    json.dumps({'filename': filename})
                ))
                
                conn.commit()
                print("播放记录已保存")
                
                self.send_json_response({
                    'code': 200,
                    'message': 'Play record saved'
                })
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"记录文件播放时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def do_OPTIONS(self):
        """处理OPTIONS请求（用于CORS预检）"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Admin-Key')
        self.end_headers()

    def handle_logs(self):
        """处理日志请求"""
        try:
            # 验证管理员密钥
            admin_key = self.headers.get('X-Admin-Key')
            if not self.config_manager.verify_admin_key(admin_key):
                self.send_error(401, 'Invalid admin key')
                return

            # 解析查询参数
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            # 获过滤参数
            start_date = query_params.get('start_date', [None])[0]
            end_date = query_params.get('end_date', [None])[0]
            action_type = query_params.get('action_type', [None])[0]

            # 获取日志
            logs = self.logger.get_logs(start_date, end_date, action_type)

            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                'code': 200,
                'message': 'success',
                'data': logs
            }
            
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))
            
        except Exception as e:
            print(f"处理日志请求失败: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

    def log_action(self, action, details):
        """记录操作日志"""
        try:
            # 添加IP地址和时间戳
            details['ip'] = self.client_address[0]
            details['user_agent'] = self.headers.get('User-Agent', 'unknown')
            
            self.logger.log(action, details)
        except Exception as e:
            print(f"记录日志失: {e}")
            print(traceback.format_exc())

    def handle_operation_query(self):
        """处理操作记录查询请求"""
        try:
            if not self.verify_admin():
                self.send_error(401, "Invalid admin key")
                return
                
            # 解析查询参数
            parsed_url = urlparse(self.path)
            params = parse_qs(parsed_url.query)
            
            filters = {
                'filename': params.get('filename', [None])[0],
                'operation_type': params.get('type', [None])[0],
                'start_date': params.get('start', [None])[0],
                'end_date': params.get('end', [None])[0]
            }
            
            # 获取操作记录
            operations = self.db_manager.get_operations(filters)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'code': 200,
                'data': operations
            }).encode())
            
        except Exception as e:
            print(f"处理操作记录查询请求失: {e}")
            self.send_error(500, str(e))

    def handle_admin_files_query(self):
        """处理管理员文件查询请求"""
        try:
            print("\n=== 处理文件查询请求 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 解析查询参数
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            filename = query_params.get('filename', [''])[0]
            status = query_params.get('status', [''])[0]
            start_date = query_params.get('start_date', [''])[0]
            end_date = query_params.get('end_date', [''])[0]
            
            print(f"查询参数:")
            print(f"- 文件名: {filename}")
            print(f"- 状态: {status}")
            print(f"- 开始日期: {start_date}")
            print(f"- 束日期: {end_date}")
            
            # 连接数据库
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 构建查询SQL
                query = """
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
                WHERE 1=1
                """
                params = []
                
                if filename:
                    query += " AND filename LIKE ?"
                    params.append(f"%{filename}%")
                    
                if status:
                    query += " AND status = ?"
                    params.append(status)
                    
                if start_date:
                    query += " AND date(upload_time) >= date(?)"
                    params.append(start_date)
                    
                if end_date:
                    query += " AND date(upload_time) <= date(?)"
                    params.append(end_date)
                    
                query += " ORDER BY upload_time DESC"
                
                print(f"执行SQL查询:")
                print(f"- SQL: {query}")
                print(f"- 参数: {params}")
                
                cursor.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                files = []
                
                for row in cursor.fetchall():
                    file_data = dict(zip(columns, row))
                    files.append(file_data)
                    
                print(f"查询到 {len(files)} 个文件")
                
                # 发送响应
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

    def handle_file_details(self):
        """处理文件详情请求"""
        try:
            print("\n=== 处理文件详情请求 ===")
            
            # 验证管理员权限
            if not self.verify_admin():
                print("管理员验证失败")
                self.send_json_error(401, "Unauthorized")
                return
                
            # 获取文件ID
            file_id = self.path.split('/')[-1]
            print(f"请求文件ID: {file_id}")
            
            # 连接数据库
            conn = sqlite3.connect('audio_server.db')
            cursor = conn.cursor()
            
            try:
                # 获取文件基本信息
                cursor.execute("""
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
                    WHERE id = ?
                """, (file_id,))
                
                file_record = cursor.fetchone()
                if not file_record:
                    print("文件不存在")
                    self.send_json_error(404, "File not found")
                    return
                    
                # 转换为字典
                columns = [desc[0] for desc in cursor.description]
                file_info = dict(zip(columns, file_record))
                
                # 获取操作日志
                cursor.execute("""
                    SELECT 
                        operation_type,
                        operation_time,
                        operator_ip,
                        details
                    FROM operation_logs 
                    WHERE file_id = ?
                    ORDER BY operation_time DESC
                """, (file_id,))
                
                operations = []
                for op in cursor.fetchall():
                    operations.append({
                        'type': op[0],
                        'time': op[1],
                        'ip': op[2],
                        'details': json.loads(op[3]) if op[3] else {}
                    })
                
                # 组装响应数据
                response_data = {
                    'code': 200,
                    'message': 'success',
                    'data': {
                        'file_info': file_info,
                        'operations': operations
                    }
                }
                
                self.send_json_response(response_data)
                print("文件详情发送成功")
                
            finally:
                conn.close()
                
        except Exception as e:
            print(f"获取文件详情时出错: {e}")
            print(traceback.format_exc())
            self.send_json_error(500, str(e))

    def serve_audio_file(self, filename):
        """服务音频文件"""
        try:
            print(f"\n=== 服务音频文件 ===")
            print(f"文件名: {filename}")
            
            file_path = os.path.join('voice', filename)
            if not os.path.exists(file_path):
                print(f"文件不存在: {file_path}")
                self.send_error(404, "File not found")
                return
                
            # 获取文件大小
            file_size = os.path.getsize(file_path)
            
            self.send_response(200)
            self.send_header('Content-Type', 'audio/mpeg')
            self.send_header('Content-Length', str(file_size))
            self.end_headers()
            
            # 读取并发送文件内容
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
                
            print("音频文件发送成功")
            
        except Exception as e:
            print(f"服务音频文件时出错: {e}")
            print(traceback.format_exc())
            self.send_error(500, str(e))

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
        print("日志管理器初始化完成")

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
            
            conn.commit()
            print("数据库初始化完成")
            
        except Exception as e:
            print(f"初始化数据库时出错: {e}")
            print(traceback.format_exc())
        finally:
            conn.close()
    
    def add_audio_file(self, file_data):
        """添加音频文件记录"""
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
