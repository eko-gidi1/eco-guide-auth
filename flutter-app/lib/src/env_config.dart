// env_config.dart
class EnvConfig {
  static String apiBaseUrl = 'http://localhost:3000'; // Default for local mock
  static String supportUrl = 'https://support.example.com'; // Default support URL

  static void load() {
    // In a real app, you'd load these from .env files or platform-specific configurations
    // For simplicity, hardcoding defaults or using flutter_dotenv package
    // For Dev Containers, localhost:3000 will route to the backend service.
    // For Flutter web running inside the container and accessing the backend in the same container,
    // 'http://localhost:3000' is correct.
  }
}