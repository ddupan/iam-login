fixture.p12 是仅用于隔离 LDAPS 测试的自签名证书和测试私钥，口令为 fixture-only。
仅信任 localhost，不能用于生产。测试账户和密码都是虚构数据。
测试服务仅绑定 127.0.0.1；JVM/Native 均执行真实 TLS、bind 和搜索，但 AD 的 UPN bind
与禁用/锁定/密码过期子码由拦截器模拟，不代替 Samba AD 人类验收。
