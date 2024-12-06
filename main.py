from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from blockchain import BlockchainModel, ArbiterAPI

if __name__ == "__main__":

    # Генерация ключей
    private_key: RsaKey = RSA.generate(2048)
    local_public_key: RsaKey = private_key.publickey()
    remote_public_key: RsaKey = ArbiterAPI.get_public_key()

    # Создание блокчейна
    blockchain: BlockchainModel = BlockchainModel()
    if not blockchain.chain:
        blockchain.create_genesis_block(private_key)

    # Добавление новых блоков
    blockchain.add_block(data={"name": "Jack", "city": "New-York"},
                         private_key=private_key)
    blockchain.add_block(data={"name": "Alex", "city": "Moscow"},
                         private_key=private_key)
    blockchain.add_block(data={"name": "Sue", "city": "Boston"},
                         private_key=private_key)

    # Вывод цепочки
    blockchain.display_chain()

    # Сохранение отдельных блоков
    blockchain.save_block(2)

    # Проверка целостности
    print(f"\nЦепочка валидна: {blockchain.is_chain_valid(local_public_key, remote_public_key)}\n")
    # >>> True

    # Изменение данных в блоке
    blockchain.chain[1].data = {"name": "Jack_1", "city": "New-York_1"}

    # Проверка целостности
    print(f"\nЦепочка валидна: {blockchain.is_chain_valid(local_public_key, remote_public_key)}\n")
    # >>> False (Хэш блока 1 поврежден)
