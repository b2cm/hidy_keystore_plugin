class BiometricPromptData {
  String? title, subtitle, negativeButton;

  BiometricPromptData({this.title, this.subtitle, this.negativeButton});

  @override
  String toString() {
    return 'BiometricPromptData{title: $title, subtitle: $subtitle, negativeButton: $negativeButton}';
  }
}
