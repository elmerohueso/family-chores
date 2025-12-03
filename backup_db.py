import os
import subprocess
from datetime import datetime, timedelta

# Database connection configuration from environment variables
POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
POSTGRES_DATABASE = os.environ.get('POSTGRES_DATABASE', 'family_chores')
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'family_chores')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'family_chores')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')

def backup_database(output_dir="backups"):

    backup_dir = "/data/backups"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"{POSTGRES_DATABASE}_backup_{timestamp}.sql")

    cmd = [
        "pg_dump",
        "-h", POSTGRES_HOST,
        "-p", POSTGRES_PORT,
        "-U", POSTGRES_USER,
        "-f", backup_file,
        POSTGRES_DATABASE
    ]

    try:
        env = os.environ.copy()
        env["PGPASSWORD"] = POSTGRES_PASSWORD
        subprocess.run(cmd, check=True, env=env)
        print(f"Backup successful: {backup_file}")
        return backup_file
    except subprocess.CalledProcessError as e:
        print(f"Backup failed: {e}")
        return None

def delete_old_backups():
    """
    Keep only the 2 most recent backup files in /data/backups.
    """
    keep = 2
    backup_dir = "/data/backups"
    if not os.path.isdir(backup_dir):
        print(f"Backup dir not found: {backup_dir}")
        return

    # Collect (mtime, path) for regular files
    files = []
    for filename in os.listdir(backup_dir):
        file_path = os.path.join(backup_dir, filename)
        if os.path.isfile(file_path) and filename.lower().endswith('.sql'):
            try:
                mtime = os.path.getmtime(file_path)
                files.append((mtime, file_path))
            except OSError:
                # Skip files we can't stat
                continue

    # Nothing to do if files are fewer than or equal to keep
    if len(files) <= keep:
        print("No old backups deleted.")
        return

    # Sort by mtime descending (newest first) and keep the first `keep`
    files.sort(key=lambda x: x[0], reverse=True)
    to_delete = files[keep:]

    deleted_files = []
    for _, file_path in to_delete:
        try:
            os.remove(file_path)
            deleted_files.append(os.path.basename(file_path))
        except OSError as e:
            print(f"Failed to delete {file_path}: {e}")

    if deleted_files:
        print(f"Deleted old backups: {', '.join(deleted_files)}")
    else:
        print("No old backups deleted.")

if __name__ == '__main__':
    backup_database()
    delete_old_backups()