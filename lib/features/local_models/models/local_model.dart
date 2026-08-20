import 'dart:convert';

class LocalModel {
  final String id;
  final String name;
  final String description;
  final String source;
  final String downloadUrl;
  final String? modelScopeId;
  final String fileName;
  final int fileSize;
  final String status;
  final double downloadProgress;
  final String localPath;
  final int createdAt;
  final String quantization;

  const LocalModel({
    required this.id,
    required this.name,
    this.description = '',
    this.source = 'hf-mirror',
    required this.downloadUrl,
    this.modelScopeId,
    required this.fileName,
    this.fileSize = 0,
    this.status = 'not_downloaded',
    this.downloadProgress = 0,
    this.localPath = '',
    this.createdAt = 0,
    this.quantization = 'Q4_K_M',
  });

  LocalModel copyWith({
    String? id, String? name, String? description, String? source,
    String? downloadUrl, List<String>? downloadUrls, String? modelScopeId, String? fileName,
    int? fileSize, String? status, double? downloadProgress,
    String? localPath, int? createdAt, String? quantization,
  }) => LocalModel(
    id: id ?? this.id, name: name ?? this.name,
    description: description ?? this.description,
    source: source ?? this.source,
    downloadUrl: downloadUrl ?? this.downloadUrl,
    modelScopeId: modelScopeId ?? this.modelScopeId,
    fileName: fileName ?? this.fileName,
    fileSize: fileSize ?? this.fileSize,
    status: status ?? this.status,
    downloadProgress: downloadProgress ?? this.downloadProgress,
    localPath: localPath ?? this.localPath,
    createdAt: createdAt ?? this.createdAt,
    quantization: quantization ?? this.quantization,
  );

  Map<String, dynamic> toJson() => {
    'id': id, 'name': name, 'description': description, 'source': source,
    'downloadUrl': downloadUrl, 'downloadUrls': downloadUrls, 'modelScopeId': modelScopeId,
    'fileName': fileName, 'fileSize': fileSize, 'status': status,
    'downloadProgress': downloadProgress, 'localPath': localPath,
    'createdAt': createdAt, 'quantization': quantization,
  };

  factory LocalModel.fromJson(Map<String, dynamic> json) => LocalModel(
    id: json['id'] as String? ?? '',
    name: json['name'] as String? ?? '',
    description: json['description'] as String? ?? '',
    source: json['source'] as String? ?? 'hf-mirror',
    downloadUrl: json['downloadUrl'] as String? ?? '',
    modelScopeId: json['modelScopeId'] as String?,
    fileName: json['fileName'] as String? ?? '',
    fileSize: json['fileSize'] as int? ?? 0,
    status: json['status'] as String? ?? 'not_downloaded',
    downloadProgress: (json['downloadProgress'] as num?)?.toDouble() ?? 0,
    localPath: json['localPath'] as String? ?? '',
    createdAt: json['createdAt'] as int? ?? 0,
    quantization: json['quantization'] as String? ?? 'Q4_K_M',
  );

  String get formattedSize {
    if (fileSize == 0) return '未知';
    if (fileSize < 1024 * 1024) return '${(fileSize / 1024).toStringAsFixed(1)} KB';
    if (fileSize < 1024 * 1024 * 1024) {
      return '${(fileSize / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(fileSize / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  String get statusLabel {
    switch (status) {
      case 'not_downloaded': return '未下载';
      case 'downloading': return '下载中';
      case 'downloaded': return '已下载';
      case 'error': return '下载失败';
      default: return status;
    }
  }

  static List<LocalModel> popularModels() => [
    LocalModel(
      id: 'qwen3.5-9b-q4', name: 'Qwen3.5-9B-Instruct',
      description: '通义千问3.5 9B聊天模型，Q4_K_M量化，推理/代码能力大幅提升',
      source: 'multi-source',
      downloadUrl: 'https://hf-mirror.com/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-Q4_K_M.gguf',
      downloadUrls: [
        'https://hf-mirror.com/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-Q4_K_M.gguf',
        'https://www.modelscope.cn/api/v1/models/qwen/Qwen3.5-9B-Instruct-GGUF/repo?Revision=master&FilePath=Qwen3.5-9B-Q4_K_M.gguf',
        'https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-Q4_K_M.gguf'
      ],
      modelScopeId: 'qwen/Qwen3.5-9B-Instruct-GGUF',
      fileName: 'Qwen3.5-9B-Q4_K_M.gguf', fileSize: 5500000000,
      quantization: 'Q4_K_M',
    ),
    LocalModel(
      id: 'qwen3.5-9b-q8', name: 'Qwen3.5-9B-Instruct',
      description: '通义千问3.5 9B聊天模型，Q8_0量化，最高精度',
      source: 'hf-mirror',
      downloadUrl: 'https://hf-mirror.com/unsloth/Qwen3.5-9B-GGUF/resolve/main/Qwen3.5-9B-Q8_0.gguf',
      modelScopeId: 'unsloth/Qwen3.5-9B-GGUF',
      fileName: 'Qwen3.5-9B-Q8_0.gguf', fileSize: 9500000000,
      quantization: 'Q8_0',
    ),
    LocalModel(
      id: 'qwen3.5-4b-q4', name: 'Qwen3.5-4B-Instruct',
      description: '通义千问3.5 4B轻量聊天模型，适合低端设备',
      source: 'hf-mirror',
      downloadUrl: 'https://hf-mirror.com/unsloth/Qwen3.5-4B-GGUF/resolve/main/Qwen3.5-4B-Q4_K_M.gguf',
      modelScopeId: 'unsloth/Qwen3.5-4B-GGUF',
      fileName: 'Qwen3.5-4B-Q4_K_M.gguf', fileSize: 2600000000,
      quantization: 'Q4_K_M',
    ),
    LocalModel(
      id: 'qwen3.5-2b-q4', name: 'Qwen3.5-2B-Instruct',
      description: '通义千问3.5 2B超轻量聊天模型，几乎任何设备都能运行',
      source: 'hf-mirror',
      downloadUrl: 'https://hf-mirror.com/unsloth/Qwen3.5-2B-GGUF/resolve/main/Qwen3.5-2B-Q4_K_M.gguf',
      modelScopeId: 'unsloth/Qwen3.5-2B-GGUF',
      fileName: 'Qwen3.5-2B-Q4_K_M.gguf', fileSize: 1200000000,
      quantization: 'Q4_K_M',
    ),
    LocalModel(
      id: 'qwen3.5-0.8b-q4', name: 'Qwen3.5-0.8B-Instruct',
      description: '通义千问3.5 0.8B微型聊天模型，极速响应',
      source: 'hf-mirror',
      downloadUrl: 'https://hf-mirror.com/unsloth/Qwen3.5-0.8B-GGUF/resolve/main/Qwen3.5-0.8B-Q4_K_M.gguf',
      modelScopeId: 'unsloth/Qwen3.5-0.8B-GGUF',
      fileName: 'Qwen3.5-0.8B-Q4_K_M.gguf', fileSize: 500000000,
      quantization: 'Q4_K_M',
    ),
    LocalModel(
      id: 'qwen3.5-35b-a3b-q4', name: 'Qwen3.5-35B-A3B',
      description: '通义千问3.5 MoE架构，35B总参/3B激活，Q4_K_M量化，兼顾大模型效果与低资源',
      source: 'hf-mirror',
      downloadUrl: 'https://hf-mirror.com/unsloth/Qwen3.5-35B-A3B-GGUF/resolve/main/Qwen3.5-35B-A3B-Q4_K_M.gguf',
      modelScopeId: 'unsloth/Qwen3.5-35B-A3B-GGUF',
      fileName: 'Qwen3.5-35B-A3B-Q4_K_M.gguf', fileSize: 20000000000,
      quantization: 'Q4_K_M',
    ),
    LocalModel(
      id: 'deepseek-r1-distill-llama-8b-q4', name: 'DeepSeek-R1-Distill-Llama-8B',
      description: 'DeepSeek R1基于Llama 3.1蒸馏版8B，推理能力强，兼容性好',
      source: 'hf-mirror',
      downloadUrl: 'https://hf-mirror.com/unsloth/DeepSeek-R1-Distill-Llama-8B-GGUF/resolve/main/DeepSeek-R1-Distill-Llama-8B-Q4_K_M.gguf',
      modelScopeId: 'unsloth/DeepSeek-R1-Distill-Llama-8B-GGUF',
      fileName: 'DeepSeek-R1-Distill-Llama-8B-Q4_K_M.gguf', fileSize: 5500000000,
      quantization: 'Q4_K_M',
    ),
    LocalModel(
      id: 'phi-3.5-mini-instruct-q4', name: 'Phi-3.5-mini-Instruct',
      description: '微软Phi-3.5 3.8B聊天模型，小尺寸高能力，适合低端设备',
      source: 'hf-mirror',
      downloadUrl: 'https://hf-mirror.com/bartowski/Phi-3.5-mini-instruct-GGUF/resolve/main/Phi-3.5-mini-instruct-Q4_K_M.gguf',
      modelScopeId: 'bartowski/Phi-3.5-mini-instruct-GGUF',
      fileName: 'Phi-3.5-mini-instruct-Q4_K_M.gguf', fileSize: 2400000000,
      quantization: 'Q4_K_M',
    ),
  ];
}
