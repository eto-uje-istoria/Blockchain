"""
.. rubric:: Модуль для реализации модели блокчейна.

Автор: Galiakhmetov Niyaz (GitHub: eto-uje-istoria)
Дата создания: 06.12.2024
Версия: 2.0.0

Описание:
Этот модуль содержит класс `BlockchainModel`, который предоставляет функционал
для работы с блокчейном. Он позволяет создавать блокчейн, добавлять новые блоки,
проверять целостность цепочки и сохранять/загружать данные блокчейна в файл.

Используемые библиотеки:
- json: для работы с JSON-файлами
- CryptoUtils: модуль для криптографических операций
- typing.List: для аннотации типов
- Block: класс для представления блока
- Crypto.PublicKey.RSA: для работы с RSA-ключами
"""

import json
from typing import List
from .Block import Block
from .CryptoUtils import CryptoUtils
from Crypto.PublicKey.RSA import RsaKey


class BlockchainModel:
    """
        Класс для управления блокчейном.

        :param storage_file: Путь к файлу для хранения цепочки блоков.
        :type storage_file: str

        :ivar storage_file: Путь к файлу, где хранится блокчейн.
        :ivar chain: Список блоков, представляющий блокчейн.
    """

    def __init__(self, storage_file: str = "data/blockchains/blockchain.json") -> None:
        """
        Инициализация модели блокчейна.

        :param storage_file: Путь к файлу для хранения цепочки.
        :type storage_file: str
        """
        self.storage_file = storage_file
        self.chain: List[Block] = []

    def create_genesis_block(self, private_key: RsaKey) -> None:
        """
        Создание первого блока (генезис-блока).

        :param private_key: Приватный ключ для подписания блока.
        :type private_key: RsaKey
        """
        genesis_block: Block = Block(index=0,
                                     data={"message": "Genesis Block"},
                                     prev_hash="0",
                                     private_key=private_key)

        self.chain.append(genesis_block)
        self.save_chain()

    def add_block(self, data: dict[str, str], private_key: RsaKey) -> None:
        """
        Добавление нового блока в цепочку.

        :param data: Данные для нового блока.
        :type data: dict
        :param private_key: Приватный ключ для подписания.
        :type private_key: RsaKey
        """
        prev_block: Block = self.chain[-1]
        new_block: Block = Block(len(self.chain), data, prev_block.hash, private_key)
        self.chain.append(new_block)
        self.save_chain()

    def is_chain_valid(self, local_public_key: RsaKey, remote_public_key: RsaKey) -> bool:
        """
        Проверка целостности цепочки блоков.

        :param local_public_key: Локальный публичный ключ для проверки данных.
        :type local_public_key: RsaKey
        :param remote_public_key: Удалённый публичный ключ для проверки хэшей.
        :type remote_public_key: RsaKey
        :return: True, если цепочка валидна, иначе False.
        :rtype: bool
        """
        for i in range(1, len(self.chain)):
            current_block: Block = self.chain[i]
            prev_block: Block = self.chain[i - 1]

            # Проверяем хэш
            if current_block.hash != current_block.calculate_hash():
                print(f"Хэш блока {current_block.index} поврежден.")
                return False

            # Проверяем подпись данных
            if not CryptoUtils.verify_data_signature(current_block.data, current_block.data_signature, local_public_key):
                print(f"Подпись данных блока {current_block.index} недействительна.")
                return False

            # Проверяем подпись хэша
            if not CryptoUtils.verify_hash_signature(current_block.hash, current_block.hash_signature, current_block.timestamp, remote_public_key):
                print(f"Подпись хэша блока {current_block.index} недействительна.")
                return False

            # Проверяем ссылку на предыдущий хэш
            if current_block.prev_hash != prev_block.hash:
                print(f"Цепочка нарушена между блоками {prev_block.index} и {current_block.index}.")
                return False

        return True

    def save_chain(self) -> None:
        """
        Сохранение цепочки блоков в файл.

        Этот метод сохраняет текущую цепочку блоков в файл в формате JSON.
        Каждый блок сохраняется как словарь, используя атрибуты объекта.

        :raises: :class:`OSError`: Если возникает ошибка при открытии файла или записи в него.
        :raises: :class:`TypeError`: Если объект `self.chain` не является списком или содержит некорректные данные для сериализации.
        :raises: :class:`json.JSONDecodeError`: Если данные не могут быть сериализованы в формат JSON.
        """
        try:
            with open(self.storage_file, "w") as file:
                json.dump([block.__dict__ for block in self.chain], file, indent=4)
        except OSError as e:
            raise OSError(f"Ошибка при открытии файла {self.storage_file}: {e}")
        except TypeError as e:
            raise TypeError(f"Ошибка при сериализации данных цепочки: {e}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Ошибка при сериализации в формат JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"Неизвестная ошибка при сохранении цепочки блоков: {e}")

    def save_block(self, block_index: int) -> None:
        """
        Сохранение отдельного блока в файл.

        Этот метод вызывает метод `save_block` из класса `Block` для сохранения блока
        в файл в формате JSON. Блок сохраняется в директории `data/blocks/`.

        :param block_index: Индекс блока для сохранения.
        :type block_index: int

        :raises: :class:`IndexError`: Если индекс блока выходит за пределы цепочки.
        :raises: :class:`RuntimeError`: Если возникла ошибка при сохранении блока.
        """
        try:
            Block.save_block(self.chain[block_index], block_index)
        except IndexError as e:
            raise IndexError(f"Блок с индексом {block_index} не найден в цепочке: {e}")
        except RuntimeError as e:
            raise RuntimeError(f"Ошибка при сохранении блока {block_index}: {e}")

    def display_chain(self) -> None:
        """
        Вывод всех блоков цепочки в консоль.
        """
        for block in self.chain:
            print(block)
