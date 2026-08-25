/// HTTP-client-agnostic Server-Sent Event.
class SseEvent {
  const SseEvent({required this.data, this.id, this.event, this.retryMillis});
  final String? id;
  final String? event;
  final String data;
  final int? retryMillis;
  Map<String, dynamic> toJson() => <String, dynamic>{
    if (id != null) 'id': id,
    if (event != null) 'event': event,
    'data': data,
    if (retryMillis != null) 'retryMillis': retryMillis,
  };
  factory SseEvent.fromJson(Map<String, dynamic> json) {
    return SseEvent(
      id: json['id'] as String?,
      event: json['event'] as String?,
      data: (json['data'] ?? '').toString(),
      retryMillis: json['retryMillis'] is int
          ? json['retryMillis'] as int
          : int.tryParse((json['retryMillis'] ?? '').toString()),
    );
  }
}
