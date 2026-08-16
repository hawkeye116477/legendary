# coding: utf-8

import os
import shutil
import hashlib
import json
import logging
import base64

from pathlib import Path
from sys import stdout
from time import perf_counter
from typing import List, Iterator

from filelock import FileLock

from legendary.models.game import VerifyResult

import keyring
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

logger = logging.getLogger('LFS Utils')


def delete_folder(path: str, recursive=True) -> bool:
    try:
        logger.debug(f'Deleting "{path}", recursive={recursive}...')
        if not recursive:
            os.removedirs(path)
        else:
            shutil.rmtree(path)
    except Exception as e:
        logger.error(f'Failed deleting files with {e!r}')
        return False
    else:
        return True


def delete_filelist(path: str, filenames: List[str],
                    delete_root_directory: bool = False,
                    silent: bool = False) -> bool:
    dirs = set()
    no_error = True

    # delete all files that were installed
    for filename in filenames:
        _dir, _fn = os.path.split(filename)
        if _dir:
            dirs.add(_dir)

        try:
            os.remove(os.path.join(path, _dir, _fn))
        except Exception as e:
            if not silent:
                logger.error(f'Failed deleting file {filename} with {e!r}')
            no_error = False

    # add intermediate directories that would have been missed otherwise
    for _dir in sorted(dirs):
        head, _ = os.path.split(_dir)
        while head:
            dirs.add(head)
            head, _ = os.path.split(head)

    # remove all directories
    for _dir in sorted(dirs, key=len, reverse=True):
        try:
            os.rmdir(os.path.join(path, _dir))
        except FileNotFoundError:
            # directory has already been deleted, ignore that
            continue
        except Exception as e:
            if not silent:
                logger.error(f'Failed removing directory "{_dir}" with {e!r}')
            no_error = False

    if delete_root_directory:
        try:
            os.rmdir(path)
        except Exception as e:
            if not silent:
                logger.error(f'Removing game directory failed with {e!r}')

    return no_error


def validate_files(base_path: str, filelist: List[tuple], hash_type='sha1',
                   large_file_threshold=1024 * 1024 * 512) -> Iterator[tuple]:
    """
    Validates the files in filelist in path against the provided hashes

    :param base_path: path in which the files are located
    :param filelist: list of tuples in format (path, hash [hex])
    :param hash_type: (optional) type of hash, default is sha1
    :param large_file_threshold: (optional) threshold for large files, default is 512 MiB
    :return: yields tuples in format (VerifyResult, path, hash [hex], bytes read)
    """

    if not filelist:
        raise ValueError('No files to validate!')

    if not os.path.exists(base_path):
        raise OSError('Path does not exist')

    for file_path, file_hash in filelist:
        full_path = os.path.join(base_path, file_path)
        # logger.debug(f'Checking "{file_path}"...')

        if not os.path.exists(full_path):
            yield VerifyResult.FILE_MISSING, file_path, '', 0
            continue

        show_progress = False
        interval = 0
        speed = 0.0
        start_time = 0.0

        try:
            _size = os.path.getsize(full_path)
            if _size > large_file_threshold:
                # enable progress indicator and go to new line
                stdout.write('\n')
                show_progress = True
                interval = (_size / (1024 * 1024)) // 100
                start_time = perf_counter()

            with open(full_path, 'rb') as f:
                real_file_hash = hashlib.new(hash_type)
                i = 0
                while chunk := f.read(1024*1024):
                    real_file_hash.update(chunk)
                    if show_progress and i % interval == 0:
                        pos = f.tell()
                        perc = (pos / _size) * 100
                        speed = pos / 1024 / 1024 / (perf_counter() - start_time)
                        stdout.write(f'\r=> Verifying large file "{file_path}": {perc:.0f}% '
                                     f'({pos / 1024 / 1024:.1f}/{_size / 1024 / 1024:.1f} MiB) '
                                     f'[{speed:.1f} MiB/s]\t')
                        stdout.flush()
                    i += 1

                if show_progress:
                    stdout.write(f'\r=> Verifying large file "{file_path}": 100% '
                                 f'({_size / 1024 / 1024:.1f}/{_size / 1024 / 1024:.1f} MiB) '
                                 f'[{speed:.1f} MiB/s]\t\n')

                result_hash = real_file_hash.hexdigest()
                if file_hash != result_hash:
                    yield VerifyResult.HASH_MISMATCH, file_path, result_hash, f.tell()
                else:
                    yield VerifyResult.HASH_MATCH, file_path, result_hash, f.tell()
        except Exception as e:
            logger.fatal(f'Could not verify "{file_path}"; opening failed with: {e!r}')
            yield VerifyResult.OTHER_ERROR, file_path, '', 0


def clean_filename(filename):
    return ''.join(i for i in filename if i not in '<>:"/\\|?*')


def get_dir_size(path):
    return sum(f.stat().st_size for f in Path(path).glob('**/*') if f.is_file())

def get_service_for_keyring(current_user_info):
    service_name = "legendary"
    if os.name == 'nt':
        service_name = f"legendary/{current_user_info["account_id"]}"
    return service_name

def remove_encryption_key(current_user_info):
    keyring.delete_password(get_service_for_keyring(current_user_info), current_user_info["account_id"])

def get_encryption_key(current_user_info):
    key = ""
    try:
        key = keyring.get_password(get_service_for_keyring(current_user_info), current_user_info["account_id"])
    except Exception:
        if current_user_info["account_id"] is not None and current_user_info[key] is not None:
            key = base64.b64encode(hashlib.sha256((current_user_info["account_id"] + current_user_info[key]).encode("utf-8")).digest()).decode("utf-8")
    final_key = ""
    if key is not None:
        final_key = base64.b64decode(key.encode('utf-8'))
    return final_key

def decrypt_file(path, current_user_info):
    try:
        key = get_encryption_key(current_user_info)
        if key is None or len(key) != 32:
            return ""
        encrypted_data = None
        with open(path, "rb") as encrypted_file_content:
            encrypted_data = encrypted_file_content.read()
        encrypted_iv = encrypted_data[:16]
        iv_cipher = AES.new(key, AES.MODE_ECB)
        iv = iv_cipher.decrypt(encrypted_iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size).decode("utf-8")
        json_decrypted_data = json.loads(decrypted_data)
    except Exception as ex:
        logger.warn(f'Failed to decrypt data with {ex!r}')
        decrypted_data = None
        json_decrypted_data = None
    return json_decrypted_data

def encrypt_to_file(path, current_user_info, data):
    encryption_key = base64.b64encode(os.urandom(32)).decode("utf-8")
    try:
        service_name = get_service_for_keyring(current_user_info)
        k_backend = keyring.core.get_keyring()
        if os.name == 'nt':
            k_backend.persist = 'local machine'
        if service_name is not None:
            try:
                remove_encryption_key(current_user_info)
            except keyring.errors.PasswordDeleteError:
                pass
            finally:
                k_backend.set_password(service_name, current_user_info["account_id"], encryption_key)
    except Exception:
        current_user_info['key'] = encryption_key
    final_encryption_key = get_encryption_key(current_user_info)
    iv_cipher = AES.new(final_encryption_key, AES.MODE_ECB)
    cipher = AES.new(final_encryption_key, AES.MODE_CBC)
    input_data = json.dumps(data).encode('utf-8')
    encrypted_data = cipher.encrypt(pad(input_data, AES.block_size))
    encrypted_iv = iv_cipher.encrypt(cipher.iv)
    with open(path, 'wb') as f:
        f.write(encrypted_iv + encrypted_data)
    return current_user_info

class LockedJSONData(FileLock):
    def __init__(self, lock_file: str):
        super().__init__(lock_file + '.lock')

        self._file_path = lock_file
        self._data = None
        self._user_data = None
        self._initial_data = None

    def __enter__(self):
        super().__enter__()

        if os.path.exists(self._file_path):
            with open(self._file_path, 'r', encoding='utf-8') as f:
                try:
                    self._user_data = json.load(f)
                    self._initial_data = self._user_data
                except json.JSONDecodeError:
                    pass
        if self._user_data and (account_id := self._user_data.get('account_id')) is not None:
            data_file_path = os.path.join(os.path.dirname(self._file_path), f"{hashlib.md5(account_id.encode('utf-8')).hexdigest()}.enc")
            if os.path.exists(data_file_path):
                self._data = decrypt_file(data_file_path, self._user_data)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        super().__exit__(exc_type, exc_val, exc_tb)

        if self._user_data is None:
            self._user_data = self._data
        new_user_data = None
        full_old_data = None
        old_data_filename = None
        if self._initial_data and (initial_account_id := self._initial_data.get('account_id')) is not None:
            old_data_filename = f"{hashlib.md5(initial_account_id.encode('utf-8')).hexdigest()}.enc"

        if self._user_data:
            new_user_data = {}
            if (account_id := self._user_data.get('account_id')) is not None:
                new_user_data['account_id'] = account_id
            if (display_name := self._user_data.get('displayName')) is not None:
                new_user_data['displayName'] = display_name
            if old_data_filename:
                full_old_data = decrypt_file(os.path.join(os.path.dirname(self._file_path), old_data_filename), self._initial_data)

        if full_old_data != self._data:
            if self._user_data and self._data and (account_id := self._user_data.get('account_id')) is not None:
                new_data_filename = f"{hashlib.md5(account_id.encode('utf-8')).hexdigest()}.enc"
                new_user_data = encrypt_to_file(os.path.join(os.path.dirname(self._file_path), new_data_filename), new_user_data, self._data)

        if self._initial_data != new_user_data:
            if new_user_data:
                with open(self._file_path, 'w', encoding='utf-8') as f:
                    json.dump(new_user_data, f, indent=2, sort_keys=True)
            else:
                if os.path.exists(self._file_path):
                    os.remove(self._file_path)

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, new_data):
        if new_data is None:
            raise ValueError('Invalid new data, use clear() explicitly to reset file data')
        self._data = new_data

    def clear(self):
        if self._user_data:
            if (account_id := self._user_data.get('account_id')) is not None:
                remove_encryption_key(self._user_data)
                new_data_file = os.path.join(os.path.dirname(self._file_path),f"{hashlib.md5(account_id.encode('utf-8')).hexdigest()}.enc")
                if os.path.exists(new_data_file):
                    os.remove(new_data_file)
            self._user_data = None
        self._data = None
