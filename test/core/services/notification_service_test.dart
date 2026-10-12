import 'package:Kelivo/core/services/notification_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test(
    'chat completion payload accepts only non-empty conversation targets',
    () {
      expect(
        NotificationService.conversationIdFromPayload(
          'chat-complete:conversation-1',
        ),
        'conversation-1',
      );
      expect(NotificationService.conversationIdFromPayload(null), isNull);
      expect(
        NotificationService.conversationIdFromPayload('conversation-1'),
        isNull,
      );
      expect(
        NotificationService.conversationIdFromPayload('chat-complete:   '),
        isNull,
      );
    },
  );

  test('notification IDs are stable and avoid foreground-service IDs', () {
    final first = NotificationService.notificationIdForConversation(
      'conversation-1',
    );
    expect(
      NotificationService.notificationIdForConversation('conversation-1'),
      first,
    );
    expect(
      NotificationService.notificationIdForConversation('conversation-2'),
      isNot(first),
    );
    expect(first, greaterThanOrEqualTo(10000));
  });

  test(
    'native cold and warm taps preserve their conversation target',
    () async {
      NotificationService.openConversation('cold');
      expect(NotificationService.takePendingConversationId(), 'cold');
      expect(NotificationService.takePendingConversationId(), isNull);
      final received = <String>[];
      final sub = NotificationService.conversationTaps.listen(received.add);
      NotificationService.openConversation('warm');
      await Future<void>.delayed(Duration.zero);
      expect(received, ['warm']);
      await sub.cancel();
    },
  );

  // [MobileBackgroundCoordinator.finish] 的通知门直接委托本谓词，所以这里锁住
  // 「何时静默」的语义；平台维度由 NotificationService.showChatCompleted 自己
  // 的门（非 Android 直接 return）负责，刻意不进入本谓词。
  group('shouldShowChatCompleted', () {
    bool gate({
      required bool notifyModeEnabled,
      required bool appInForeground,
      required bool homeRouteVisible,
      required bool isCurrentConversation,
    }) => NotificationService.shouldShowChatCompleted(
      notifyModeEnabled: notifyModeEnabled,
      appInForeground: appInForeground,
      homeRouteVisible: homeRouteVisible,
      isCurrentConversation: isCurrentConversation,
    );

    test('notify mode off never notifies, even in background', () {
      expect(
        gate(
          notifyModeEnabled: false,
          appInForeground: false,
          homeRouteVisible: false,
          isCurrentConversation: true,
        ),
        isFalse,
      );
      expect(
        gate(
          notifyModeEnabled: false,
          appInForeground: true,
          homeRouteVisible: true,
          isCurrentConversation: true,
        ),
        isFalse,
      );
    });

    test('background completion notifies', () {
      expect(
        gate(
          notifyModeEnabled: true,
          appInForeground: false,
          homeRouteVisible: true,
          isCurrentConversation: true,
        ),
        isTrue,
      );
    });

    test('foreground on the same visible conversation is silent', () {
      expect(
        gate(
          notifyModeEnabled: true,
          appInForeground: true,
          homeRouteVisible: true,
          isCurrentConversation: true,
        ),
        isFalse,
      );
    });

    test('foreground elsewhere still notifies', () {
      expect(
        gate(
          notifyModeEnabled: true,
          appInForeground: true,
          homeRouteVisible: true,
          isCurrentConversation: false,
        ),
        isTrue,
      );
      expect(
        gate(
          notifyModeEnabled: true,
          appInForeground: true,
          homeRouteVisible: false,
          isCurrentConversation: true,
        ),
        isTrue,
      );
    });
  });
}
