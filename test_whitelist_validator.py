#!/usr/bin/env python3
"""
test_whitelist_validator.py — Комплексный набор тестов для автономного анализатора Белых Списков (БС) РФ.
"""

import unittest
from whitelist_validator import (
    load_sni_database,
    load_cidr_database,
    is_whitelisted_sni,
    is_whitelisted_ip,
    parse_link_parameters,
    evaluate_whitelist_criteria,
)
from generate_subscriptions import (
    is_true_whitelist_config,
    format_subscription,
    extract_ping,
    extract_speed,
)

class TestWhitelistValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sni_count = load_sni_database()
        cls.cidr_count = load_cidr_database()

    def test_database_loading(self):
        """Проверка успешной загрузки баз SNI и CIDR."""
        self.assertGreater(self.sni_count, 20000, "База SNI должна содержать >20k доменов")
        self.assertGreater(self.cidr_count, 25000, "База CIDR должна содержать >25k подсетей")

    def test_sni_whitelisting(self):
        """Проверка соответствия российских SNI и их поддоменов."""
        # Прямые домены и ключевые сервисы
        ok, reason = is_whitelisted_sni("yandex.ru")
        self.assertTrue(ok, f"yandex.ru должен быть в БС, reason={reason}")

        ok, reason = is_whitelisted_sni("vk.com")
        self.assertTrue(ok, f"vk.com должен быть в БС, reason={reason}")

        ok, reason = is_whitelisted_sni("gosuslugi.ru")
        self.assertTrue(ok, f"gosuslugi.ru должен быть в БС, reason={reason}")

        # Поддомены
        ok, reason = is_whitelisted_sni("api.vk.com")
        self.assertTrue(ok, f"api.vk.com должен определяться по корню vk.com, reason={reason}")

        ok, reason = is_whitelisted_sni("sub.portal.yandex.ru")
        self.assertTrue(ok, f"sub.portal.yandex.ru должен определяться по корню yandex.ru, reason={reason}")

        # Небелый список
        ok, _ = is_whitelisted_sni("google.com")
        self.assertFalse(ok, "google.com не должен быть в российском БС")

        ok, _ = is_whitelisted_sni("netflix.com")
        self.assertFalse(ok, "netflix.com не должен быть в российском БС")

    def test_cidr_ip_matching(self):
        """Проверка принадлежности IP к российским подсетям БС."""
        # 2.63.0.1 входит в 2.63.0.0/17 (первая строка whitelist_cidr.txt)
        ok, reason = is_whitelisted_ip("2.63.0.1")
        self.assertTrue(ok, f"2.63.0.1 должен входить в 2.63.0.0/17, reason={reason}")

        # IP зарубежных сетей
        ok, _ = is_whitelisted_ip("8.8.8.8")
        self.assertFalse(ok, "8.8.8.8 (Google DNS) не должен быть в российском CIDR БС")

    def test_link_parsing(self):
        """Проверка извлечения параметров конфигураций."""
        link = "vless://abcd-1234@45.130.125.69:443?security=tls&sni=vk.com&type=ws&fp=firefox#Test%20Config"
        params = parse_link_parameters(link)
        self.assertIsNotNone(params)
        self.assertEqual(params["proto"], "vless")
        self.assertEqual(params["host"], "45.130.125.69")
        self.assertEqual(params["port"], 443)
        self.assertEqual(params["sni"], "vk.com")
        self.assertEqual(params["fp"], "firefox")
        self.assertEqual(params["remark"], "Test Config")

    def test_evaluate_whitelist_criteria(self):
        """Проверка полной классификации конфигураций на БС."""
        # 1. Конфиг с российским SNI
        bs_link = "vless://user@1.2.3.4:443?security=tls&sni=yandex.ru&type=ws#Server 1"
        is_bs, reason, _ = evaluate_whitelist_criteria(bs_link)
        self.assertTrue(is_bs)
        self.assertIn("SNI White", reason)

        # 2. Конфиг с российским IP
        bs_ip_link = "vless://user@2.63.0.1:443?security=tls&sni=foreign.com#Server 2"
        is_bs, reason, _ = evaluate_whitelist_criteria(bs_ip_link)
        self.assertTrue(is_bs)
        self.assertIn("CIDR White", reason)

        # 3. Чисто зарубежный конфиг
        foreign_link = "vless://user@8.8.8.8:443?security=tls&sni=google.com#Foreign"
        is_bs, reason, _ = evaluate_whitelist_criteria(foreign_link)
        self.assertFalse(is_bs)

    def test_generate_subscriptions_helpers(self):
        """Проверка вспомогательных функций подписок."""
        link = "vless://user@host:443?sni=yandex.ru#⚡ 120ms 5.5MB/s Server"
        self.assertTrue(is_true_whitelist_config(link))
        self.assertEqual(extract_ping(link), 120)
        self.assertAlmostEqual(extract_speed(link), 5.5)

    def test_subscription_headers_formatting(self):
        """Проверка форматирования заголовков для клиентов (title, desc, update time, counts)."""
        configs = [
            "vless://u1@1.2.3.4:443?sni=vk.com#cfg1",
            "vless://u2@2.3.4.5:443?sni=yandex.ru#cfg2"
        ]
        text = format_subscription(
            configs,
            "ОСТАТЬСЯ НА СВЯЗИ [ТЕСТ]",
            "sub_test.txt",
            "Тестовое описание подписки"
        )
        self.assertIn("# !name=", text)
        self.assertIn("# profile-title: base64:", text)
        self.assertIn("#profile-title:", text)
        self.assertIn("# !desc=", text)
        self.assertIn("# !url=", text)
        self.assertIn("2 конфигов", text)
        self.assertIn("sub_test.txt", text)

if __name__ == "__main__":
    unittest.main()
