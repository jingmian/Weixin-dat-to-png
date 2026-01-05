#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
微信图片解密脚本 - 基于 sjzar/chatlog Go源码逻辑重制版
参考:
1. pkg/util/dat2img/dat2img.go (核心解密算法)
2. internal/chatlog/manager.go (路径处理逻辑)
"""

import os
import struct
import hashlib
from pathlib import Path
from typing import Optional, Tuple
import json

# 尝试导入 AES，如果未安装则提示
try:
    from Crypto.Cipher import AES
except ImportError:
    print("错误: 缺少 pycryptodome 库。请运行: pip install pycryptodome")
    exit(1)

class WeChatImageDecryptor:
    def __init__(self, config: dict):
        self.config = config
        self.img_key = config.get('img_key', '')
        
        # --- 逻辑修正：严格处理 XOR Key 类型 ---
        # 对应 Go 中的 defaultXorKey
        raw_xor = config.get('xor_key', 0x37)
        if isinstance(raw_xor, str):
            if raw_xor.lower().startswith('0x'):
                self.xor_key = int(raw_xor, 16)
            else:
                try:
                    self.xor_key = int(raw_xor)
                except ValueError:
                    self.xor_key = 0x37
        else:
            self.xor_key = int(raw_xor)

        # 图片头魔数定义 (参考 dat2img.go 中的 magic number)
        self.magic_numbers = {
            'jpg': [0xFF, 0xD8, 0xFF],
            'png': [0x89, 0x50, 0x4E, 0x47],
            'gif': [0x47, 0x49, 0x46, 0x38],
            'bmp': [0x42, 0x4D],
            'tiff': [0x49, 0x49, 0x2A, 0x00],
            'wxgf': [0x77, 0x78, 0x67, 0x66] # 微信动态图格式
        }
        
        # V4 格式定义 (参考 dat2img.go)
        self.v4_formats = {
            # V4_1 使用固定 Key
            b'\x07\x08\x56\x31': b'cfcd208495d565ef',
            # V4_2 使用配置中的 ImgKey
            b'\x07\x08\x56\x32': bytes.fromhex(self.img_key) if self.img_key else b'\x00'*16
        }

    def decrypt_file(self, file_path: str) -> Tuple[bytes, str]:
        """主解密入口"""
        print(f"正在读取文件: {file_path}")
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 4:
            raise ValueError("文件数据过短")

        # 1. 尝试 V4 格式匹配 (参考 dat2img.go Decode 函数)
        # 读取前4字节判断是否为 V4
        header_sig = data[:4]
        if header_sig in self.v4_formats:
            aes_key = self.v4_formats[header_sig]
            print(f"检测到 V4 格式加密 ({header_sig.hex()})")
            return self._decrypt_v4(data, aes_key)

        # 2. 否则使用 V3 (XOR) 解密
        # print("检测到 V3/XOR 格式加密")
        return self._decrypt_xor(data)

    def _decrypt_v4(self, data: bytes, aes_key: bytes) -> Tuple[bytes, str]:
        """
        V4 解密逻辑
        对应 dat2img.go 中的 DecodeV4
        结构: [Head 15 bytes] [AES Encrypted Chunk] [Middle Plain Text] [XOR Encrypted Tail]
        """
        # 头部解析
        # offset 6-10: AES长度 (int32 little endian)
        aes_len = struct.unpack('<I', data[6:10])[0]
        # offset 10-14: XOR长度 (int32 little endian)
        xor_len = struct.unpack('<I', data[10:14])[0]
        
        raw_payload = data[15:] # 跳过15字节头部
        
        # --- 关键逻辑对齐 ---
        # Go逻辑: aesDecodeLen := (aesLen/16 + 1) * 16
        # 这意味着它读取的是对齐后的长度，但有效数据只有 aesLen
        aes_decode_len = (aes_len // 16 + 1) * 16
        
        if aes_decode_len > len(raw_payload):
            aes_decode_len = len(raw_payload)

        # 1. AES 解密部分
        aes_ciphertext = raw_payload[:aes_decode_len]
        aes_plaintext_chunk = self._aes_decrypt(aes_ciphertext, aes_key)
        
        # 截取有效数据 (Go代码是通过切片 [:aesLen] 来截取的，而不是 unpad)
        decrypted_head = aes_plaintext_chunk[:aes_len]
        
        # 2. 中间明文部分
        middle_start = aes_decode_len
        middle_end = len(raw_payload) - xor_len
        middle_data = b''
        if middle_start < middle_end:
            middle_data = raw_payload[middle_start:middle_end]
            
        # 3. 尾部 XOR 部分
        decrypted_tail = b''
        if xor_len > 0:
            tail_ciphertext = raw_payload[middle_end:]
            # 尾部使用默认 XOR Key (0x37) 或配置 Key
            decrypted_tail = bytes(b ^ self.xor_key for b in tail_ciphertext)
            
        # 拼接
        final_data = decrypted_head + middle_data + decrypted_tail
        ext = self._detect_format(final_data)
        return final_data, ext

    def _decrypt_xor(self, data: bytes) -> Tuple[bytes, str]:
        """
        V3/XOR 解密逻辑
        对应 dat2img.go 中的 DecodeXor
        逻辑：尝试匹配常见文件头来反推 Key，如果匹配失败则使用默认 Key
        """
        # 尝试通过文件头猜测 key
        first_byte = data[0]
        detected_key = None
        
        for fmt, header in self.magic_numbers.items():
            # 假设 key = data[0] ^ header[0]
            # 比如: data[0]是 0xAB, JPG头是 0xFF, 那么 key = 0xAB ^ 0xFF
            guess_key = first_byte ^ header[0]
            
            # 验证: 用这个 key 解密后面几个字节，看是否匹配 header
            is_match = True
            for i in range(len(header)):
                if i >= len(data): 
                    is_match = False
                    break
                if (data[i] ^ guess_key) != header[i]:
                    is_match = False
                    break
            
            if is_match:
                detected_key = guess_key
                # print(f"自动识别为 {fmt} 格式，计算出的 XOR Key: {hex(detected_key)}")
                break
        
        # 决定使用的 Key
        final_key = detected_key if detected_key is not None else self.xor_key
        
        # 解密
        decrypted_data = bytes(b ^ final_key for b in data)
        ext = self._detect_format(decrypted_data)
        return decrypted_data, ext

    def _aes_decrypt(self, data: bytes, key: bytes) -> bytes:
        if not data: return b''
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data)

    def _detect_format(self, data: bytes) -> str:
        """根据解密后的数据头判断扩展名"""
        for fmt, header in self.magic_numbers.items():
            # 转换为 bytes 进行比较
            header_bytes = bytes(header)
            if data.startswith(header_bytes):
                return fmt
        return 'jpg' # 默认回退

    def _find_file_recursive(self, root_dir: str, target_filename: str) -> Optional[str]:
        """
        递归查找文件 (优先级增强版)
        优先返回原图 (.dat)，找不到才返回缩略图 (_t.dat)
        """
        print(f"正在目录 {root_dir} 中搜索文件: {target_filename}...")
        
        target_hash = os.path.basename(target_filename).split('.')[0]
        
        # 用于存储找到的候选文件
        candidates = {
            'original': None, # 原图
            'thumb': None     # 缩略图
        }

        for root, dirs, files in os.walk(root_dir):
            for file in files:
                # 检查文件名是否包含 Hash
                if target_hash in file:
                    full_path = os.path.join(root, file)
                    
                    # 判断是原图还是缩略图
                    if "_t.dat" in file or "_t" in file:
                        if candidates['thumb'] is None:
                            candidates['thumb'] = full_path
                    else:
                        # 找到了疑似原图 (不含 _t)
                        candidates['original'] = full_path
                        # 如果找到了原图，通常可以直接返回了，因为这是最高优先级
                        print(f"找到原图: {file}")
                        return full_path

        # 遍历结束后，如果没有原图，才返回缩略图
        if candidates['original']:
            return candidates['original']
        elif candidates['thumb']:
            print(f"警告: 未找到原图，退而求其次使用缩略图: {os.path.basename(candidates['thumb'])}")
            return candidates['thumb']
            
        return None

    def process_task(self, task_payload: dict, data_dir: str) -> str:
        contents = task_payload.get('contents', {})
        # 获取原始路径 (可能是 Windows 路径)
        raw_path = contents.get('path', '')
        if not raw_path:
            raise ValueError("Payload 中没有 path 字段")
            
        # 提取文件名
        file_hash_name = os.path.basename(raw_path.replace('\\', '/'))
        
        # 1. 尝试按照相对路径查找 (如果目录结构一致)
        # ... 这里省略，直接用最稳妥的递归查找
        
        # 2. 递归查找文件
        file_path = self._find_file_recursive(data_dir, file_hash_name)
        
        if not file_path:
             raise FileNotFoundError(f"在 {data_dir} 下找不到文件: {file_hash_name}")
             
        # 解密
        decrypted_data, ext = self.decrypt_file(file_path)
        
        # 保存
        output_dir = Path('decrypted_images')
        output_dir.mkdir(exist_ok=True)
        
        # 计算 MD5 (对应 manager.go 中的 output 命名逻辑)
        md5_hash = hashlib.md5(decrypted_data).hexdigest()
        output_file = output_dir / f"{md5_hash}.{ext}"
        
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
            
        return str(output_file)

def load_config():
    config_file = 'wechat_decrypt_config.json'
    if not os.path.exists(config_file):
        print(f"配置文件 {config_file} 不存在")
        exit(1)
    with open(config_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def main():
    config = load_config()
    decryptor = WeChatImageDecryptor(config)
    
    # 你的 Payload 数据
    task_payload = {
        "contents": {
            "md5": "3c59dc048e8850243be8079a5c74d079",
            "path": "msg\\attach\\3c59dc048e8850243be8079a5c74d079\\2025-02\\Img\\3c59dc048e8850243be8079a5c74d079"
        }
    }
    
    try:
        output_path = decryptor.process_task(task_payload, config['data_dir'])
        print(f"SUCCESS: 图片已保存至 -> {output_path}")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()