import hashlib
import io
import json
import os
import random
import zipfile

import asyncio


IMPRINT_FILE_NAME = 'imprint.json'
SHARD_MAX_SIZE = 10 * 1024 * 1024
SHARD_BATCH_SIZE = 100


class Sharder(object):
    def __init__(self, location, imprint_location):
        self.location = location
        self.imprint_file = os.path.join(imprint_location, IMPRINT_FILE_NAME)

        self.imprint = self.__reconcile_imprint()

    async def __generate_file_imprint(self, root, filename):
        file_path = os.path.join(root, filename)
        with open(file_path, 'rb') as f:
            contents = f.read()
            hash_id = hashlib.sha256(contents).hexdigest()
            local_path = file_path.replace(self.location, '')
            return {'path': local_path, 'hash_id': hash_id, 'size': len(contents)}

    def __find_files(self):
        files_to_shard = []
        event_loop = asyncio.get_event_loop()

        for root, _, filenames in os.walk(self.location):
            tasks = []
            for filename in filenames:
                tasks.append(self.__generate_file_imprint(root, filename))

            future = asyncio.gather(*tasks)
            files_to_shard += event_loop.run_until_complete(future)

        event_loop.close()

        return files_to_shard

    def __create_imprint(self, shards, files):
        with open(self.imprint_file, 'w') as f:
            imprint = {'shards': shards, 'files': files}
            json.dump(imprint, f)

    # Need to make this function much faster
    def __get_corrupted_shards(self, imprint, local_files):
        corrupted_shards = []
        found_files = []
        for historic_file_imprint in imprint.get('files', []):
            found = False
            historic_hash_id = historic_file_imprint.get('hash_id')

            for i, file_imprint in enumerate(local_files):
                hash_id = file_imprint.get('hash_id')
                if hash_id == historic_hash_id:
                    found = True
                    found_files.append({**historic_file_imprint, **file_imprint})
                    local_files.pop(i)
                    break

            if not found:
                shard_id = historic_file_imprint.get('shard_id')
                if shard_id not in corrupted_shards:
                    corrupted_shards.append(shard_id)

        return corrupted_shards, found_files

    def __reconcile_imprint(self):
        imprint = {'shards': [], 'files': []}
        if not os.path.isfile(self.imprint_file):
            with open(self.imprint_file, 'w') as f:
                json.dump(imprint, f)
        else:
            with open(self.imprint_file, 'r') as f:
                imprint = json.load(f)

        print('Analysing directory: %s' % self.location)
        local_files = self.__find_files()

        # Figure out what shards have been corrupted
        # Shards are: ["sdkjsdj", "sdjsdsd"]
        # Files are: {"hash_id": "alknlas", shard_id: "sdkjsdj", size: 9823}
        print('Finding corrupted shards')
        corrupted_shards, found_files = self.__get_corrupted_shards(imprint, local_files)
        clean_shards = []
        for shard_id in imprint.get('shards', []):
            if shard_id not in corrupted_shards:
                clean_shards.append(shard_id)

        missing_files = len(imprint.get('files')) - len(found_files)

        # Now need to determine what old files to include in new shard creations
        print('Determining which old files need new shards')
        clean_files = []
        unassigned_files = []
        for fileinfo in found_files:
            shard_id = fileinfo.get('shard_id')
            if shard_id in corrupted_shards:
                fileinfo.pop('shard_id')
                unassigned_files.append(fileinfo)
            else:
                fileinfo.pop('path')
                clean_files.append(fileinfo)

        # Commit clean stuff to imprint
        self.__create_imprint(clean_shards, clean_files)

        for fileinfo in local_files:
            file_id = fileinfo.get('hash_id')
            if file_id not in [found['hash_id'] for found in found_files]:
                unassigned_files.append(fileinfo)

        print('There are %d missing/changed files from imprint' % missing_files)
        print('Detected %d corrupted shards' % len(corrupted_shards))
        print('Commited %d clean shards to imprint' % len(clean_shards))
        print('There are %d files to shard' % len(unassigned_files))

        self.clean_shards = clean_shards
        self.clean_files = clean_files
        self.corrupted_shards = corrupted_shards
        self.unassigned_files = unassigned_files

    def get_shard_deletions(self):
        return self.corrupted_shards

    def __generate_shard(self, ram_file, shard_files):
        ram_file.seek(0)
        contents = ram_file.read()
        shard_id = hashlib.sha256(contents).hexdigest()
        self.clean_shards.append(shard_id)

        for sharded_fileinfo in shard_files:
            sharded_fileinfo.pop('path')
            sharded_fileinfo['shard_id'] = shard_id
            self.clean_files.append(sharded_fileinfo)

        self.__create_imprint(self.clean_shards, self.clean_files)
        return shard_id, contents

    def get_new_shards(self):
        # This function acts as a generator, creating & yielding shards to be
        # sent to the api
        os.chdir(self.location)

        shard_size = 0
        shard_files = []
        ram_file = io.BytesIO()
        ziped = zipfile.ZipFile(ram_file, 'w')

        left = len(self.unassigned_files)
        batches = []
        start = 0
        end = SHARD_BATCH_SIZE
        while True:
            batches.append(self.unassigned_files[start:end])
            start += SHARD_BATCH_SIZE
            end += SHARD_BATCH_SIZE

            if start > left:
                break

            if end > left:
                end = left

        left = len(batches)
        while left:
            index = random.randint(0, left-1)
            batch = batches.pop(index)

            for fileinfo in batch:
                size = fileinfo.get('size', 0)
                if shard_size + size > SHARD_MAX_SIZE:
                    ziped.close()

                    yield self.__generate_shard(ram_file, shard_files)

                    shard_size = 0
                    shard_files = []
                    ram_file = io.BytesIO()
                    ziped = zipfile.ZipFile(ram_file, 'w')

                ziped.write(fileinfo.get('path'))
                shard_size += size
                shard_files.append(fileinfo)

            left -= 1
            if left <= 0:
                ziped.close()
                yield self.__generate_shard(ram_file, shard_files)
