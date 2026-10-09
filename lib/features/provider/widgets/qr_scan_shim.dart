/// 扫码能力的占位实现。
///
/// 我方端侧裁剪移除了 `mobile_scanner` 依赖，但导入供应商的「相册识别二维码」
/// 入口仍在。这里提供一个永远识别不到结果的 shim，保证 UI 结构不塌、失败路径
/// 走既有的「未识别到二维码」提示；后续要恢复真扫码时，替换成本文件即可。
class MobileScannerController {
  const MobileScannerController();

  Future<Object?> analyzeImage(String path) async => null;
}
