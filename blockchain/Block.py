"""
.. rubric:: Модуль для реализации блока в блокчейне.

Автор: Galiakhmetov Niyaz (GitHub: eto-uje-istoria)
Дата создания: 05.12.2024
Версия: 1.0.0

Описание:
Этот модуль содержит класс `Block`, который используется для представления
основного элемента блокчейна. Каждый блок включает индекс, данные, хэш
предыдущего блока, подпись данных и текущий хэш.

Используемые библиотеки:
- hashlib: для хэширования данных
- json: для сериализации блока в JSON
- CryptoUtils: кастомный модуль для работы с криптографией
- Crypto.PublicKey.RSA: для работы с RSA-ключами
"""

import hashlib
import json
from typing import Union
from .CryptoUtils import CryptoUtils
from Crypto.PublicKey.RSA import RsaKey


class Block:
    """
        Класс для представления блока в блокчейне.

        :param index: Индекс блока в цепочке.
        :type index: int
        :param data: Данные, которые хранятся в блоке.
        :type data: dict
        :param prev_hash: Хэш предыдущего блока.
        :type prev_hash: str
        :param private_key: Приватный ключ RSA, используемый для подписания данных и хэша.
        :type private_key: RsaKey

        :ivar index: индекс блока
        :ivar data: пользовательские данные
        :ivar prev_hash: хэш предыдущего блока
        :ivar data_signature: подпись данных
        :ivar hash: хэш текущего блока
        :ivar hash_signature: подпись хэша блока
        """

    def __init__(self, index: int, data: dict[str, str], prev_hash: str, private_key: RsaKey) -> None:
        """
        Инициализация нового блока.

        :param index: Индекс блока.
        :type index: int
        :param data: Данные, которые хранятся в блоке.
        :type data: dict
        :param prev_hash: Хэш предыдущего блока.
        :type prev_hash: str
        :param private_key: Приватный ключ RSA для подписания.
        :type private_key: RsaKey
        """
        self.index = index
        self.data = data
        self.prev_hash = prev_hash
        self.data_signature = CryptoUtils.sign_data(data, private_key)
        self.hash = self.calculate_hash()
        self.hash_signature = CryptoUtils.sign_hash(self.hash, private_key)

    def calculate_hash(self) -> str:
        """
        Вычисление хэша текущего блока.

        Хэш создаётся на основе индекса, данных, хэша предыдущего блока
        и подписи данных.

        :return: Строковое представление хэша блока.
        :rtype: str
        """
        block_content = f"{self.index}{self.data}{self.prev_hash}{self.data_signature}"
        return hashlib.sha256(block_content.encode()).hexdigest()

    def save_block(self, block_index: int) -> None:
        """
        Сохранение блока в файл в формате JSON.

        Блок сохраняется в директории `data/blocks/` под именем `block_{block_index}.json`.

        :param block_index: Индекс блока, используемый для имени файла.
        :type block_index: int

        :raises: :class:`FileNotFoundError`: Если директория для сохранения блока не существует.
        :raises: :class:`OSError`: Если возникает ошибка при открытии файла или записи в него.
        :raises: :class:`TypeError`: Если объект не может быть сериализован в формат JSON.
        """
        try:
            with open(f"data/blocks/block_{block_index}.json", "w") as file:
                json.dump(self.__dict__, file, indent=4)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Директория для блока {block_index} не найдена: {e}")
        except OSError as e:
            raise OSError(f"Ошибка при открытии файла для блока {block_index}: {e}")
        except TypeError as e:
            raise TypeError(f"Ошибка при сериализации блока {block_index} в JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"Неизвестная ошибка при сохранении блока {block_index}: {e}")

    def __str__(self) -> str:
        """
        Возвращает строковое представление блока в формате JSON.

        :return: JSON-строка, представляющая блок.
        :rtype: str
        """
        return json.dumps({
            "index": self.index,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "data_signature": self.data_signature,
            "hash": self.hash,
            "hash_signature": self.hash_signature
        }, indent=4)
