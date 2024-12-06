"""
.. rubric:: Модуль для криптографических операций в блокчейне.

Автор: Galiakhmetov Niyaz (GitHub: eto-uje-istoria)
Дата создания: 06.12.2024
Версия: 2.0.0

Описание:
Этот модуль содержит утилиты для криптографической обработки данных,
включая подпись данных и хэшей с использованием RSA-ключей, а также
проверку подписей. Он использует библиотеку PyCryptodome для
работы с криптографией.

Используемые библиотеки:
- json: для сериализации данных
- Crypto.Hash.SHA256: для вычисления хэша данных
- Crypto.Signature.pkcs1_15: для подписания и проверки подписей
- Crypto.PublicKey.RSA: для работы с RSA-ключами
"""
import binascii
import json
from .ArbiterAPI import ArbiterAPI
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


class CryptoUtils:
    """
        Утилиты для работы с криптографией в контексте блокчейна.

        Класс предоставляет методы для подписания данных и хэшей, а также
        для проверки подписей с использованием RSA-ключей.
    """

    TIMESTAMP: str = None

    @staticmethod
    def sign_data(data: dict[str, str], private_key: RsaKey) -> str:
        """
        Подписание данных с использованием приватного ключа.

        Этот метод создает хэш данных, а затем подписывает его с помощью
        предоставленного приватного ключа RSA.

        :param data: Данные, которые нужно подписать.
        :type data: dict
        :param private_key: Приватный ключ RSA для подписания.
        :type private_key: RsaKey
        :return: Подпись данных в виде шестнадцатеричной строки.
        :rtype: str

        :raises: :class:`ValueError`: Если данные не могут быть сериализованы в формат JSON.
        :raises: :class:`TypeError`: Если ключ имеет неподдерживаемый тип.
        """
        try:
            data_hash: SHA256Hash = SHA256.new(json.dumps(data).encode())
            signer: PKCS115_SigScheme = pkcs1_15.new(private_key)
            return signer.sign(data_hash).hex()
        except (ValueError, TypeError) as e:
            raise ValueError("Ошибка при сериализации данных или типе ключа.") from e

    @staticmethod
    def sign_hash(hash_: str) -> str:
        """
        Подписание хэша с использованием приватного ключа от Арбитра (API).

        Этот метод подписывает хэш Арбитром (API).

        :param hash_: Хэш, который нужно подписать.
        :type hash_: str
        :return: Подпись хэша в виде шестнадцатеричной строки.
        :rtype: str

        :raises: :class:`ValueError`: Если хэш не может быть обработан.
        :raises: :class:`TypeError`: Если ключ имеет неподдерживаемый тип.
        """
        try:
            response = ArbiterAPI.get_signature(hash_)
            hash_signature = response['signature']
            CryptoUtils.TIMESTAMP = response['ts']
            return hash_signature
        except (ValueError, TypeError) as e:
            raise ValueError("Ошибка при обработке хэша или типе ключа.") from e

    @staticmethod
    def verify_data_signature(data: dict[str, str], signature: str, public_key: RsaKey) -> bool:
        """
        Проверка подписи данных с использованием публичного ключа.

        Этот метод проверяет, что подпись данных действительна, используя
        публичный ключ RSA.

        :param data: Данные, для которых была сделана подпись.
        :type data: dict
        :param signature: Подпись данных в шестнадцатеричной строке.
        :type signature: str
        :param public_key: Публичный ключ RSA для проверки подписи.
        :type public_key: RsaKey
        :return: True, если подпись действительна, иначе False.
        :rtype: bool

        :raises: :class:`ValueError`: Если подпись не может быть проверена.
        :raises: :class:`TypeError`: Если ключ имеет неподдерживаемый тип.
        """
        try:
            data_hash: SHA256Hash = SHA256.new(json.dumps(data).encode())
            pkcs1_15.new(public_key).verify(data_hash, bytes.fromhex(signature))
            return True
        except (ValueError, TypeError) as e:
            raise ValueError("Ошибка при проверке подписи данных или типе ключа.") from e

    @staticmethod
    def verify_hash_signature(hash_: str, signature: str, timestamp: str, remote_public_key: RsaKey) -> bool:
        """
        Проверка подписи хэша с использованием публичного ключа.

        Этот метод проверяет, что подпись хэша действительна, используя
        публичный ключ RSA.

        :param hash_: Хэш, для которого была сделана подпись.
        :type hash_: str
        :param signature: Подпись хэша в шестнадцатеричной строке.
        :type signature: str
        :param remote_public_key: Публичный ключ от Арбитра
        :type remote_public_key: `RsaKey`
        :param timestamp: Дата подписи хэша
        :type timestamp: str
        :return: True, если подпись действительна, иначе False.
        :rtype: bool

        :raises: :class:`ValueError`: Если подпись не может быть проверена.
        :raises: :class:`TypeError`: Если ключ имеет неподдерживаемый тип.
        """
        token = timestamp.encode('utf-8') + binascii.unhexlify(hash_)
        hash_object: SHA256Hash = SHA256.new(token)
        try:
            pkcs1_15.new(remote_public_key).verify(hash_object, bytes.fromhex(signature))
            return True
        except (ValueError, TypeError) as e:
            raise ValueError("Ошибка при проверке подписи хэша или типе ключа.") from e

    @staticmethod
    def get_timestamp() -> str:
        return CryptoUtils.TIMESTAMP
