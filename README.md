# Weixin-dat-to-png 微信图片解密使用说明

## 准备工作

将微信 `msg` 目录移动到项目根目录下：

```bash
cp -r /path/to/wechat/msg ./msg
```

## 配置文件

`wechat_decrypt_config.json` 配置说明：

### img_key

图片解密密钥，需要使用[sjzar/chatlog 项目](https://github.com/sjzar/chatlog)获取。

```json
{
  "version": 4,
  "img_key": "e10adc3949ba59abbe56e057f20f883e",
  "xor_key": "0x37",
  "data_dir": "./msg"
}
```

## 获取图片信息

调用 sjzar/chatlog API 获取图片 md5 和 path：

```bash
curl "http://localhost:5030/api/v1/chatlog?time=2025-02-27~2025-02-27&talker=3231237@chatroom&limit=100&format=json"
```

返回示例：

```json
{
  "messages": [
    {
      "md5": "e10adc3949ba59abbe56e057f20f883e",
      "path": "msg\\attach\\c4ca4238a0b923820dcc509a6f75849b\\2025-02\\Img\\3c59dc048e8850243be8079a5c74d079"
    }
  ]
}
```

## 解密图片

修改 `decrypt.py` 中的 `task_payload`：

```python
task_payload = {
    "contents": {
        "md5": "从API获取的md5",
        "path": "从API获取的path"
    }
}
```

运行解密：

```bash
python3 decrypt.py
```

解密后的图片保存在 `decrypted_images/` 目录，文件名为 `{md5}.{ext}`。



