"""
.. rubric:: Модуль для взаимодействия с API арбитра.

Автор: Galiakhmetov Niyaz (GitHub: eto-uje-istoria)
Дата создания: 06.12.2024
Версия: 2.0.0

Описание:
Этот модуль реализует класс `ArbiterAPI`, который предоставляет методы для взаимодействия
с API арбитра. Он позволяет запрашивать подписи хэшей блоков и управлять коммуникацией
с внешним сервисом через HTTP-запросы.

Используемые библиотеки:
- requests: для выполнения HTTP-запросов
- Crypto.PublicKey.RSA: для работы с ключами RSA
"""

import requests
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from requests import Response


class ArbiterAPI:
    """
        Класс для работы с API арбитра.

        Этот класс предоставляет методы для взаимодействия с API арбитра, включая
        отправку данных для подписи и обработку ответов.
    """

    BASE_URL: str = "http://itislabs.ru/ts"

    @staticmethod
    def get_signature(digest: str) -> dict[str, str]:
        """
        Запрос подписи для указанного хэша у API арбитра.

        :param digest: Хэш, который требуется подписать.
        :type digest: str
        :return: Подпись в виде строки, если запрос успешен, иначе None.
        :rtype: dict[str, str]

        :raises: Исключение, если запрос завершился с ошибкой.
        """
        url: str = f"{ArbiterAPI.BASE_URL}?digest={digest}"
        response: Response = requests.get(url)

        if response.status_code != 200:
            raise ValueError(f"Ошибка при получении подписи: {response.status_code}, {response.text}")

        result = response.json()
        if result.get("status") != 0:
            raise ValueError(f"Арбитр вернул ошибку: {result.get('statusString', 'Неизвестная ошибка')}")

        return result["timeStampToken"]

    @staticmethod
    def get_public_key() -> RsaKey:
        """
        Проверка подписи с использованием API арбитра.

        :return: True, если подпись валидна, иначе False.
        :rtype: bool

        :raises: Исключение, если запрос завершился с ошибкой.
        """
        url: str = f"{ArbiterAPI.BASE_URL}/public"
        response: Response = requests.get(url)

        if response.status_code != 200:
            raise ValueError(f"Ошибка при получении публичного ключа: {response.status_code}, {response.text}")

        public_key_str: str = response.text
        try:
            public_key_bytes = bytes.fromhex(public_key_str)
            public_key: RsaKey = RSA.import_key(public_key_bytes)
            return public_key
        except ValueError:
            raise ValueError(f"Некорректный формат публичного ключа: {public_key_str}")
