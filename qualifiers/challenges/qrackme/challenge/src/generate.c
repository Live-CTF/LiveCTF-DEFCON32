int main() {
  rc4_state_t rc4;
  char* key = "Access denied. ";
  char* str = "LiveCTF{One!AhAhAhTwo!AhAhAh!Three!}";
  size_t len = strlen(str);
  rc4_init(&rc4, key, strlen(key));
  rc4_crypt(&rc4, str, len);
  write(1, str, len);
}
