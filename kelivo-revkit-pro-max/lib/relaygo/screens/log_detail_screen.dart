import 'package:flutter/material.dart';
import 'package:Kelivo/relaygo/config/theme.dart';
import 'package:Kelivo/relaygo/models/request_log.dart';
import 'package:Kelivo/relaygo/utils/formatters.dart';
import 'package:Kelivo/relaygo/l10n/app_strings.dart';

/// 请求日志详情页
///
/// 点击日志列表条目进入，完整展示单条请求的字段：
/// 请求行（方法 + 路径）、服务商 / Key / 模型、状态与耗时、
/// token 用量、字节数、流式 / 重试 / 缓存 / 限流标记、错误信息与时间。
class LogDetailScreen extends StatelessWidget {
  final RequestLog log;

  LogDetailScreen({Key? key, required this.log}) : super(key: key);

  Color _statusColor(BuildContext context) {
    if (log.isError) return Th.danger(context);
    if (log.statusCode >= 400 && log.statusCode < 500) return Th.warning(context);
    return Th.success(context);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(L10n.tr('日志详情')),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Center(
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
                decoration: BoxDecoration(
                  color: _statusColor(context).withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  '${log.statusCode}',
                  style: TextStyle(
                    fontFamily: AppTheme.monoFontFamily,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    color: _statusColor(context),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
        children: [
          _section(context, L10n.tr('请求'), [
            _kv(context, 'Method', log.method),
            _kv(context, 'Path', log.path, mono: true, wrap: true),
          ]),
          _section(context, L10n.tr('路由'), [
            _kv(context, L10n.tr('服务商'), log.provider),
            _kv(context, L10n.tr('Key 名称'), log.keyName),
            _kv(context, 'Key', log.keyMasked, mono: true),
            _kv(context, L10n.tr('模型'), log.model, mono: true, wrap: true),
            if (log.actualModel.isNotEmpty &&
                log.actualModel != log.model)
              _kv(context, L10n.tr('实际模型'), log.actualModel, mono: true, wrap: true),
            if (log.ruleName != null && log.ruleName!.isNotEmpty)
              _kv(context, L10n.tr('路由规则'), log.ruleName!),
          ]),
          _section(context, L10n.tr('结果'), [
            _kv(context, L10n.tr('状态码'), '${log.statusCode}', mono: true),
            _kv(context, L10n.tr('耗时'), Formatters.formatDuration(log.durationMs)),
            if (log.totalTokens > 0) ...[
              _kv(context, 'Prompt tokens', Formatters.formatNumber(log.promptTokens),
                  mono: true),
              _kv(context, 'Completion tokens',
                  Formatters.formatNumber(log.completionTokens),
                  mono: true),
              _kv(context, L10n.tr('总 tokens'), Formatters.formatNumber(log.totalTokens),
                  mono: true),
            ],
            _kv(context, L10n.tr('请求字节'), Formatters.formatNumber(log.requestBytes),
                mono: true),
            _kv(context, L10n.tr('响应字节'), Formatters.formatNumber(log.responseBytes),
                mono: true),
          ]),
          _section(context, L10n.tr('标记'), [
            _kv(context, L10n.tr('流式'), log.streaming ? L10n.tr('是') : L10n.tr('否')),
            _kv(context, L10n.tr('重试次数'), '${log.retries}'),
            _kv(context, L10n.tr('命中缓存'), log.cached ? L10n.tr('是') : L10n.tr('否')),
            _kv(context, L10n.tr('限流维度'),
                log.rateLimited.isEmpty ? L10n.tr('无') : log.rateLimited),
          ]),
          if (log.error != null && log.error!.isNotEmpty)
            _section(context, L10n.tr('错误'), [
              Container(
                width: double.infinity,
                padding: EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Th.dangerSoft(context),
                  borderRadius: BorderRadius.circular(AppTheme.radiusMd),
                  border: Border.all(color: Th.danger(context).withValues(alpha: 0.3)),
                ),
                child: SelectableText(
                  log.error!,
                  style: TextStyle(
                    fontSize: 13,
                    color: Th.danger(context),
                    fontFamily: AppTheme.monoFontFamily,
                    height: 1.5,
                  ),
                ),
              ),
            ]),
          _section(context, L10n.tr('时间'), [
            _kv(context, L10n.tr('时间戳'), Formatters.formatDateTime(log.timestamp), mono: true),
            _kv(context, L10n.tr('日志 ID'), log.id, mono: true, wrap: true),
          ]),
        ],
      ),
    );
  }

  Widget _section(BuildContext context, String title, List<Widget> children) {
    return Padding(
      padding: EdgeInsets.only(bottom: 18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w700,
              color: Th.text2(context),
            ),
          ),
          const SizedBox(height: 8),
          Container(
            width: double.infinity,
            padding: EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(AppTheme.radiusMd),
              border: Border.all(color: Th.border(context)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: children,
            ),
          ),
        ],
      ),
    );
  }

  Widget _kv(BuildContext context, String label, String value, {bool mono = false, bool wrap = false}) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 118,
            child: Text(
              label,
              style: TextStyle(fontSize: 13, color: Th.text3(context)),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                fontSize: 13,
                color: Th.text(context),
                fontFamily: mono ? AppTheme.monoFontFamily : null,
                fontWeight: mono ? FontWeight.w600 : FontWeight.w400,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
