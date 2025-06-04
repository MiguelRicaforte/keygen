import os
import time
import hmac
import base64
import hashlib
import logging
import datetime
from typing import Final, Optional
import requests
import pandas as pd
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
import re

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- Admin settings and bot token ---
# Full admin(s) with unrestricted control:
ADMIN_USER_IDS: Final = [6554018668]
# Sub-admin(s) who can only /gen and have a limited wallet:
SUB_ADMIN_USER_IDS: Final = [
    6863249420,
    5422559512
]

TOKEN: Final = '7588778933:AAGC-B5ZDnfhGNx4kpCnAGf0XUC0HyimJd4'
SECRET_KEY: Final = b'sandokenkanen'

# File paths
CSV_FILE: Final = "hwid_data.csv"
PAUSED_CSV_FILE: Final = "paused_keys.csv"
SUBADMIN_CSV_FILE: Final = "subadmin_wallets.csv"

# --- Time retrieval (unchanged) ---
def get_http_time(offset_hours=8):
    url = "https://oras.pagasa.dost.gov.ph/"
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/115.0.0.0 Safari/537.36")
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        html_text = response.text  # Get raw HTML content
        match = re.search(r"var currenttime = '(.*?)'", html_text)
        if not match:
            logger.warning("Could not locate time string on PAGASA site.")
            raise ValueError("Time string not found")
        time_text = match.group(1)
        logger.info("Retrieved time from PAGASA: %s", time_text)
        dt = datetime.datetime.strptime(time_text, "%B %d, %Y %I:%M:%S %p")
        timestamp = dt.timestamp()
        logger.info("PAGASA Time in 24-hour format: %s", dt.strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("PAGASA Unix Timestamp: %s", timestamp)
        return int(timestamp)
    except Exception as e:
        logger.warning("Time server 1 (PAGASA) failed, trying server 2. Error: %s", e)
        try:
            r = requests.get("https://www.timeapi.io/api/time/current/zone?timeZone=Asia%2FManila", timeout=10)
            r.raise_for_status()
            data = r.json()
            datetime_str = data["dateTime"]
            if "." in datetime_str:
                datetime_str = datetime_str.replace('Z', '+00:00')
                if '+' in datetime_str:
                    main_part, tz_part = datetime_str.split('+', 1)
                    tz_info = '+' + tz_part
                elif '-' in datetime_str and 'T' in datetime_str:
                    main_part, tz_part = datetime_str.split('-', 1)
                    tz_info = '-' + tz_part
                else:
                    main_part = datetime_str
                    tz_info = ""
                if "." in main_part:
                    dt_part, micro_part = main_part.split(".")
                    micro_part = micro_part[:6]
                    parsable_str = f"{dt_part}.{micro_part}{tz_info}"
                    dt_format = "%Y-%m-%dT%H:%M:%S.%f%z" if tz_info else "%Y-%m-%dT%H:%M:%S.%f"
                else:
                     parsable_str = f"{main_part}{tz_info}"
                     dt_format = "%Y-%m-%dT%H:%M:%S%z" if tz_info else "%Y-%m-%dT%H:%M:%S"
            else: # Handle if no microseconds part
                 datetime_str = datetime_str.replace('Z', '+00:00')
                 if '+' in datetime_str:
                     main_part, tz_part = datetime_str.split('+', 1)
                     tz_info = '+' + tz_part
                 elif '-' in datetime_str and 'T' in datetime_str:
                     main_part, tz_part = datetime_str.split('-', 1)
                     tz_info = '-' + tz_part
                 else:
                     main_part = datetime_str
                     tz_info = ""
                 parsable_str = f"{main_part}{tz_info}"
                 dt_format = "%Y-%m-%dT%H:%M:%S%z" if tz_info else "%Y-%m-%dT%H:%M:%S"

            dt = datetime.datetime.strptime(parsable_str, dt_format)
            unix_time = int(dt.timestamp())
            logger.info("Retrieved time from timeapi.io (Unix): %d", unix_time)
            return unix_time
        except requests.exceptions.RequestException as e2:
            logger.error("Time server 2 (timeapi.io) failed: %s", e2)
            return None
        except Exception as e2:
            logger.error("Error processing time from timeapi.io: %s", e2)
            return None

# --- Duration parsing helpers ---

def parse_duration(duration: str, current_time: int) -> Optional[int]:
    """As before: returns expiration timestamp (current_time + requested)."""
    duration = duration.lower()
    try:
        if duration.endswith('h'):
            hours = int(duration[:-1]); return current_time + hours * 3600
        elif duration.endswith('d'):
            days = int(duration[:-1]); return current_time + days * 86400
    except ValueError:
        pass
    return None

def parse_duration_seconds(duration: str) -> Optional[int]:
    """Returns just the number of seconds for a duration like '12h' or '7d'."""
    duration = duration.lower()
    try:
        if duration.endswith('h'):
            return int(duration[:-1]) * 3600
        elif duration.endswith('d'):
            return int(duration[:-1]) * 86400
    except ValueError:
        pass
    return None

# --- Sub-admin wallet persistence ---

def load_subadmin_wallets() -> pd.DataFrame:
    cols = ['user_id', 'remaining_seconds']
    if not os.path.exists(SUBADMIN_CSV_FILE):
        return pd.DataFrame(columns=cols)
    try:
        df = pd.read_csv(SUBADMIN_CSV_FILE)
        df['user_id'] = df['user_id'].astype(int)
        df['remaining_seconds'] = pd.to_numeric(df['remaining_seconds'], errors='coerce').fillna(0).astype(int)
        return df
    except Exception as e:
        logger.error("Error loading subadmin wallets: %s", e, exc_info=True)
        return pd.DataFrame(columns=cols)

def save_subadmin_wallets(df: pd.DataFrame) -> bool:
    try:
        df = df[['user_id', 'remaining_seconds']]
        df['user_id'] = df['user_id'].astype(int)
        df['remaining_seconds'] = df['remaining_seconds'].astype(int)
        df.to_csv(SUBADMIN_CSV_FILE, index=False)
        return True
    except Exception as e:
        logger.error("Failed to save %s: %s", SUBADMIN_CSV_FILE, e, exc_info=True)
        return False

def update_subadmin_wallet(user_id: int, delta_seconds: int) -> None:
    df = load_subadmin_wallets()
    if user_id in df['user_id'].values:
        df.loc[df['user_id'] == user_id, 'remaining_seconds'] += delta_seconds
    else:
        df = pd.concat([df, pd.DataFrame([{
            'user_id': user_id,
            'remaining_seconds': delta_seconds
        }])], ignore_index=True)
    # Prevent negative balances:
    df.loc[df['remaining_seconds'] < 0, 'remaining_seconds'] = 0
    save_subadmin_wallets(df)

def get_subadmin_balance(user_id: int) -> int:
    df = load_subadmin_wallets()
    row = df[df['user_id'] == user_id]
    return int(row['remaining_seconds'].iloc[0]) if not row.empty else 0

# --- CSV and key generation (unchanged) ---

def save_key_details(name: str, hwid: str, expiration_time: int) -> bool:
    """
    Save or update the username, HWID, and expiration time in the active CSV file.
    Returns True on success, False on failure.
    """
    # Ensure name is lowercase for saving
    name = name.lower()
    hwid = str(hwid) # Ensure hwid is string
    try:
        df = pd.DataFrame(columns=['name', 'hwid', 'expiration_time']) # Default empty
        if os.path.exists(CSV_FILE):
            try:
                df = pd.read_csv(CSV_FILE)
                # Ensure columns exist and have correct types for comparison
                df['name'] = df['name'].astype(str)
                df['hwid'] = df['hwid'].astype(str)
                df['expiration_time'] = pd.to_numeric(df['expiration_time'], errors='coerce')
            except pd.errors.EmptyDataError:
                logger.warning("%s exists but is empty. Initializing new DataFrame.", CSV_FILE)
                df = pd.DataFrame(columns=['name', 'hwid', 'expiration_time'])
            except Exception as read_err:
                logger.error("Error reading existing CSV file %s: %s", CSV_FILE, read_err)
                return False # Indicate failure

        if name in df['name'].values:
            # Update existing user based on name
            df.loc[df['name'] == name, ['hwid', 'expiration_time']] = [hwid, expiration_time]
            logger.info("Updated key details for user: %s", name)
        else:
            # Add new user
            new_row = pd.DataFrame([{'name': name, 'hwid': hwid, 'expiration_time': expiration_time}])
            df = pd.concat([df, new_row], ignore_index=True)
            logger.info("Added new key details for user: %s", name)

        # Ensure consistent types before saving
        df['name'] = df['name'].astype(str)
        df['hwid'] = df['hwid'].astype(str)
        df['expiration_time'] = df['expiration_time'].astype(float).astype(int) # Ensure numeric->int
        df.to_csv(CSV_FILE, index=False)
        return True

    except Exception as e:
        logger.error("Failed to save key details for user %s: %s", name, e, exc_info=True)
        return False

def retrieve_hwid(name: str) -> Optional[str]:
    """
    Retrieve the HWID for the given username (case-insensitive) from the active CSV file.
    Returns None if the user is not found or an error occurs.
    """
    # Use lowercase for lookup
    name_lower = name.lower()
    if not os.path.exists(CSV_FILE):
        logger.warning("CSV file %s not found for HWID retrieval.", CSV_FILE)
        return None
    try:
        df = pd.read_csv(CSV_FILE)
        df['name'] = df['name'].astype(str).str.lower() # Compare lowercase
        user_data = df[df['name'] == name_lower]
        if not user_data.empty:
            return str(user_data['hwid'].iloc[0]) # Ensure HWID is returned as string
        else:
            logger.info("HWID not found for user: %s", name)
            return None
    except pd.errors.EmptyDataError:
        logger.warning("CSV file %s is empty.", CSV_FILE)
        return None
    except Exception as e:
        logger.error("Error retrieving HWID for %s: %s", name, e)
        return None

def generate_key(expiration_time: int, hwid: str, user_name: str) -> str:
    message = f"{expiration_time},{hwid},{user_name.lower()}".encode('utf-8')
    signature = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(message + signature).decode('utf-8')


# --- Paused-key helpers (unchanged) ---
def load_paused_keys() -> pd.DataFrame:
    """Loads the paused keys CSV file into a DataFrame."""
    cols = ['hwid', 'name', 'remaining_seconds', 'paused_at']
    if not os.path.exists(PAUSED_CSV_FILE):
        logger.info(f"{PAUSED_CSV_FILE} not found, returning empty DataFrame.")
        return pd.DataFrame(columns=cols)
    try:
        df = pd.read_csv(PAUSED_CSV_FILE)
        if not all(col in df.columns for col in cols):
             missing = [col for col in cols if col not in df.columns]
             logger.error(f"{PAUSED_CSV_FILE} is missing required columns: {', '.join(missing)}. Returning empty.")
             return pd.DataFrame(columns=cols)
        df['hwid'] = df['hwid'].astype(str)
        df['name'] = df['name'].astype(str).str.lower() # Store/compare lowercase names
        df['remaining_seconds'] = pd.to_numeric(df['remaining_seconds'], errors='coerce')
        df['paused_at'] = pd.to_numeric(df['paused_at'], errors='coerce')
        df.dropna(subset=['remaining_seconds', 'paused_at'], inplace=True)
        df['remaining_seconds'] = df['remaining_seconds'].astype(int)
        df['paused_at'] = df['paused_at'].astype(int)
        return df
    except pd.errors.EmptyDataError:
        logger.warning(f"{PAUSED_CSV_FILE} is empty.")
        return pd.DataFrame(columns=cols)
    except Exception as e:
        logger.error(f"Error loading {PAUSED_CSV_FILE}: {e}", exc_info=True)
        return pd.DataFrame(columns=cols)

def save_paused_keys(df: pd.DataFrame) -> bool:
    """Saves the DataFrame to the paused keys CSV file."""
    try:
        # Ensure consistent types before saving
        df['hwid'] = df['hwid'].astype(str)
        df['name'] = df['name'].astype(str).str.lower() # Save lowercase names
        df['remaining_seconds'] = df['remaining_seconds'].astype(int)
        df['paused_at'] = df['paused_at'].astype(int)
        df = df[['hwid', 'name', 'remaining_seconds', 'paused_at']] # Ensure column order
        df.to_csv(PAUSED_CSV_FILE, index=False)
        logger.info(f"Successfully saved data to {PAUSED_CSV_FILE}")
        return True
    except Exception as e:
        logger.error(f"Failed to save {PAUSED_CSV_FILE}: {e}", exc_info=True)
        return False

def format_seconds(total_seconds: int) -> str:
    if total_seconds <= 0: return "0m"
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts = []
    if days > 0: parts.append(f"{days}d")
    if hours > 0: parts.append(f"{hours}h")
    if minutes > 0 or not parts: parts.append(f"{minutes}m")
    return " ".join(parts) if parts else "< 1m"


def find_user_by_name(name_to_find: str) -> Optional[pd.Series]:
    """Finds user data by name (case-insensitive) in the main active CSV_FILE."""
    name_lower = name_to_find.lower()
    if not os.path.exists(CSV_FILE):
        return None
    try:
        df = pd.read_csv(CSV_FILE)
        df['name'] = df['name'].astype(str).str.lower() # Compare lowercase
        user_data = df[df['name'] == name_lower]
        return user_data.iloc[0] if not user_data.empty else None
    except pd.errors.EmptyDataError:
        return None
    except Exception as e:
        logger.error(f"Error searching for name '{name_to_find}' in {CSV_FILE}: {e}")
        return None

def find_paused_user_by_name(name_to_find: str) -> Optional[pd.Series]:
    """Finds paused user data by name (case-insensitive) in the PAUSED_CSV_FILE."""
    name_lower = name_to_find.lower()
    paused_df = load_paused_keys() # Load fresh data with type checks
    if paused_df.empty:
        return None
    # Names are already lowercase from load_paused_keys()
    user_data = paused_df[paused_df['name'] == name_lower]
    return user_data.iloc[0] if not user_data.empty else None

def remove_active_user_by_name(name_to_remove: str) -> bool:
    """Removes a user row by name (case-insensitive) from the main CSV_FILE."""
    name_lower = name_to_remove.lower()
    if not os.path.exists(CSV_FILE):
        logger.warning(f"Attempted to remove name '{name_to_remove}' but {CSV_FILE} not found.")
        return False
    try:
        df = pd.read_csv(CSV_FILE)
        df['name_lower'] = df['name'].astype(str).str.lower() # Temp col for comparison
        initial_len = len(df)
        df_filtered = df[df['name_lower'] != name_lower]
        df_filtered = df_filtered.drop(columns=['name_lower']) # Remove temp col

        if len(df_filtered) < initial_len:
             df_filtered.to_csv(CSV_FILE, index=False)
             logger.info(f"Removed user with name '{name_to_remove}' from {CSV_FILE}")
             return True
        else:
             logger.warning(f"Name '{name_to_remove}' not found in {CSV_FILE} for removal.")
             return False
    except pd.errors.EmptyDataError:
        logger.warning(f"{CSV_FILE} is empty, cannot remove name '{name_to_remove}'.")
        return False
    except Exception as e:
        logger.error(f"Error removing name '{name_to_remove}' from {CSV_FILE}: {e}")
        return False

def remove_paused_user_by_name(name_to_remove: str) -> bool:
    """Removes a user row by name (case-insensitive) from the PAUSED_CSV_FILE."""
    name_lower = name_to_remove.lower()
    paused_df = load_paused_keys()
    if paused_df.empty:
         logger.warning(f"Attempted to remove paused user '{name_to_remove}' but file is empty/not found.")
         return False

    initial_len = len(paused_df)
    # Names are already lowercase from load_paused_keys()
    paused_df_filtered = paused_df[paused_df['name'] != name_lower]

    if len(paused_df_filtered) < initial_len:
         return save_paused_keys(paused_df_filtered) # Use save function for consistency
    else:
         logger.warning(f"Paused user name '{name_to_remove}' not found in {PAUSED_CSV_FILE} for removal.")
         return False

# --- Command Handlers --- #

async def generate_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """ /gen <username> <duration> [hwid] -- now works for full-admin and sub-admin (wallet-limited) """
    user_id = update.message.from_user.id

    # Only full-admin or sub-admin may /gen
    if user_id not in ADMIN_USER_IDS and user_id not in SUB_ADMIN_USER_IDS:
        await update.message.reply_text("❌ You do not have permission.")
        return

    args = context.args
    if len(args) < 2:
        await update.message.reply_text("⚠️ Usage: /gen <username> <duration (e.g., 12h, 7d)> [hwid]")
        return

    name = args[0].lower()
    duration_str = args[1]
    provided_hwid = args[2] if len(args) >= 3 else None

    current_time = get_http_time()
    if current_time is None:
        await update.message.reply_text("❌ Error: Could not retrieve current time.")
        return

    expiration_time = parse_duration(duration_str, current_time)
    if expiration_time is None:
        await update.message.reply_text("❌ Invalid duration format (e.g., `24h`, `3d`).")
        return

    # Sub-admin wallet check & deduction
    if user_id in SUB_ADMIN_USER_IDS:
        seconds_needed = expiration_time - current_time
        balance = get_subadmin_balance(user_id)
        if seconds_needed > balance:
            await update.message.reply_text(
                f"❌ Insufficient wallet balance. You have {format_seconds(balance)} remaining."
            )
            return
        # Deduct
        update_subadmin_wallet(user_id, -seconds_needed)

    # Retrieve or require HWID
    hwid_to_use = provided_hwid or retrieve_hwid(name)
    if not hwid_to_use:
        await update.message.reply_text(
            f"❓ User `{name}` not registered. Please provide the HWID: "
            f"`/gen {name} {duration_str} <HWID>`"
        )
        return
    hwid_to_use = str(hwid_to_use)

    # Save and generate key
    if not save_key_details(name, hwid_to_use, expiration_time):
        await update.message.reply_text(f"❌ Error saving key details to {CSV_FILE}.")
        return

    key = generate_key(expiration_time, hwid_to_use, name)
    expiration_dt = datetime.datetime.fromtimestamp(expiration_time)
    date_str = expiration_dt.strftime('%Y-%m-%d %H:%M:%S %Z')

    await update.message.reply_text(
        f"✅ Key generated for `{name}`!\n"
        f"HWID: `{hwid_to_use}`\n"
        f"Expires on: `{date_str}`\n\n"
        f"🔑 Key:\n`{key}`",
        parse_mode='Markdown'
    )


async def addwallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /addwallet <sub_admin_id> <duration>
    Adds time to a sub-admin's wallet. Duration like '30d' or '12h'.
    """
    user_id = update.message.from_user.id
    if user_id not in ADMIN_USER_IDS:
        await update.message.reply_text("❌ You do not have permission.")
        return

    args = context.args
    if len(args) != 2:
        await update.message.reply_text("⚠️ Usage: /addwallet <sub_admin_id> <duration>")
        return

    try:
        sub_id = int(args[0])
    except ValueError:
        await update.message.reply_text("❌ `<sub_admin_id>` must be a numeric Telegram user ID.")
        return

    if sub_id not in SUB_ADMIN_USER_IDS:
        await update.message.reply_text("❌ That user is not configured as a sub-admin.")
        return

    duration_str = args[1]
    seconds = parse_duration_seconds(duration_str)
    if seconds is None:
        await update.message.reply_text("❌ Invalid duration format. Use e.g. `30d` or `12h`.")
        return

    update_subadmin_wallet(sub_id, seconds)
    new_balance = get_subadmin_balance(sub_id)
    await update.message.reply_text(
        f"✅ Added `{duration_str}` to sub-admin `{sub_id}`’s wallet.\n"
        f"New balance: `{format_seconds(new_balance)}`."
    )

# --- Restrict other commands to full-admin only ---

async def check_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /check command:
    Lists all active, expired, and paused keys, then sends
    hwid_data.csv, paused_keys.csv, and subadmin_wallets.csv as backups.
    """
    user_id = update.message.from_user.id
    if user_id not in ADMIN_USER_IDS:
        await update.message.reply_text("❌ You do not have permission.")
        return

    # Load active and paused data
    active_df = pd.DataFrame(columns=['name', 'hwid', 'expiration_time'])
    paused_df = load_paused_keys()

    active_file_exists = os.path.exists(CSV_FILE)
    if active_file_exists:
        try:
            active_df = pd.read_csv(CSV_FILE)
            if active_df.empty:
                active_file_exists = False
        except pd.errors.EmptyDataError:
            active_file_exists = False
        except Exception as e:
            logger.error(f"Error reading {CSV_FILE}: {e}", exc_info=True)
            await update.message.reply_text(f"❌ Error reading `{CSV_FILE}`.")
            return

    if not active_file_exists and paused_df.empty:
        await update.message.reply_text("ℹ️ No key data found.")
        return

    # Build the status overview
    processed = []
    now = int(time.time())

    # Active keys
    if active_file_exists and not active_df.empty:
        required = ['name', 'hwid', 'expiration_time']
        if all(c in active_df.columns for c in required):
            active_df['expiration_time'] = pd.to_numeric(active_df['expiration_time'], errors='coerce')
            active_df.dropna(subset=['expiration_time'], inplace=True)
            active_df['expiration_time'] = active_df['expiration_time'].astype(int)
            active_df['seconds_left'] = active_df['expiration_time'] - now

            for _, row in active_df.iterrows():
                status = "🔴 Expired" if row['seconds_left'] <= 0 else "🟢 Active "
                sort_flag = 2 if status.startswith("🔴") else 1
                time_str = "---" if status.startswith("🔴") else format_seconds(row['seconds_left'])
                processed.append({
                    'name': row['name'],
                    'status': status,
                    'time': time_str,
                    'sort1': sort_flag,
                    'sort2': row['expiration_time']
                })
        else:
            logger.warning(f"{CSV_FILE} missing columns.")

    # Paused keys
    for _, row in paused_df.iterrows():
        processed.append({
            'name': row['name'],
            'status': "⏸️ Paused ",
            'time': format_seconds(row['remaining_seconds']),
            'sort1': 3,
            'sort2': row['name']
        })

    if not processed:
        await update.message.reply_text("ℹ️ No valid or paused keys found.")
        return

    # Sort and format text
    processed.sort(key=lambda x: (x['sort1'], x['sort2']))
    maxlen = max(len(p['name']) for p in processed)
    lines = ["📊 **Key Status Overview**", "---"]
    header = f"`{'Username'.ljust(maxlen)} | Status      | Time Left`"
    lines += [header, "`" + "-"*(len(header.strip('`'))) + "`"]
    for p in processed:
        lines.append(f"`{p['name'].ljust(maxlen)} | {p['status'].ljust(11)} | {p['time'].ljust(10)}`")

    text = "\n".join(lines)
    if len(text) > 4096:
        await update.message.reply_text("⚠️ Output too long, sending CSVs instead.")
    else:
        await update.message.reply_text(text, parse_mode='Markdown')

    # Finally, send all three CSVs as attachments if they exist
    for path in [CSV_FILE, PAUSED_CSV_FILE, SUBADMIN_CSV_FILE]:
        if os.path.exists(path):
            with open(path, 'rb') as f:
                await update.message.reply_document(
                    f,
                    filename=os.path.basename(path),
                    caption=f"Backup of `{os.path.basename(path)}`"
                )


async def get_csv_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """ /get command: Sends the active hwid_data.csv file. """
    user_id = update.message.from_user.id
    if user_id not in ADMIN_USER_IDS:
        await update.message.reply_text("❌ You do not have permission.")
        return
    if not os.path.exists(CSV_FILE):
        await update.message.reply_text(f"❓ File `{CSV_FILE}` not found.")
        return
    try:
        await update.message.reply_text(f"⬇️ Sending `{CSV_FILE}`...", parse_mode='Markdown')
        with open(CSV_FILE, 'rb') as cf:
            await update.message.reply_document(cf, CSV_FILE, f"Active key data {datetime.datetime.now():%Y-%m-%d %H:%M}")
        logger.info(f"Admin {user_id} received {CSV_FILE}")
    except Exception as e:
        logger.error(f"Failed send {CSV_FILE} to admin {user_id}: {e}")
        await update.message.reply_text("❌ Error sending file.")


async def set_csv_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /setcsv  —  Accepts upload of any of the bot’s CSVs
    (hwid_data.csv, paused_keys.csv, subadmin_wallets.csv) and restores it.
    """
    user_id = update.message.from_user.id
    if user_id not in ADMIN_USER_IDS:
        return  # ignore silently

    doc = update.message.document
    if not doc or not doc.file_name.lower().endswith(".csv"):
        await update.message.reply_text("❌ Please upload a `.csv` file with caption `/setcsv`.")
        return

    name = doc.file_name.lower()
    mapping = {
        "hwid_data.csv": CSV_FILE,
        "paused_keys.csv": PAUSED_CSV_FILE,
        "subadmin_wallets.csv": SUBADMIN_CSV_FILE
    }
    if name not in mapping:
        await update.message.reply_text(
            "❌ Unrecognized CSV. Upload one of: `hwid_data.csv`, "
            "`paused_keys.csv`, `subadmin_wallets.csv`."
        )
        return

    target = mapping[name]
    tmp = f"{target}.tmp"

    # Download to temp
    file = await context.bot.get_file(doc.file_id)
    await file.download_to_drive(tmp)

    # Optional: validate columns based on which file
    # e.g. if name == "subadmin_wallets.csv": ...
    # Skipping for brevity

    # Backup old
    if os.path.exists(target):
        bak = f"{target}.bak_{datetime.datetime.now():%Y%m%d%H%M%S}"
        os.rename(target, bak)
        logger.info(f"Backed up {target} → {bak}")

    # Replace
    os.rename(tmp, target)
    await update.message.reply_text(f"✅ `{os.path.basename(target)}` restored successfully.")


async def pause_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /pause command:
    Usage: /pause <username>
    Pauses the key for the user (case-insensitive), saving remaining time.
    """
    user_id = update.message.from_user.id
    if user_id not in ADMIN_USER_IDS:
        await update.message.reply_text("❌ You do not have permission.")
        return

    args = context.args
    if len(args) != 1:
        await update.message.reply_text("⚠️ Usage: /pause <username>")
        return

    # --- Pause by name (lowercase) ---
    name_to_pause = args[0].lower()
    current_time = int(time.time())

    # 1. Check if already paused
    if find_paused_user_by_name(name_to_pause) is not None:
        await update.message.reply_text(f"❌ Error: User `{name_to_pause}` is already paused.")
        return

    # 2. Find the user in the active keys file by name
    user_data = find_user_by_name(name_to_pause)
    if user_data is None:
        await update.message.reply_text(f"❌ Error: User `{name_to_pause}` not found in active keys.")
        return

    # 3. Extract details and calculate remaining time
    try:
        hwid = str(user_data['hwid']) # Get HWID from active data
        expiration_time = int(user_data['expiration_time'])
    except (KeyError, ValueError) as e:
         await update.message.reply_text(f"❌ Error reading data for `{name_to_pause}`. Corrupted? {e}")
         logger.error(f"Data error for name {name_to_pause} in {CSV_FILE}: {e}")
         return

    remaining_seconds = expiration_time - current_time
    if remaining_seconds <= 0:
        await update.message.reply_text(f"❌ Error: Key for `{name_to_pause}` already expired. Cannot pause.")
        return

    # 4. Add to paused list
    paused_df = load_paused_keys()
    new_paused_entry = pd.DataFrame([{
        'hwid': hwid, # Use the retrieved HWID
        'name': name_to_pause, # Already lowercase
        'remaining_seconds': remaining_seconds,
        'paused_at': current_time
    }])
    updated_paused_df = pd.concat([paused_df, new_paused_entry], ignore_index=True)

    if not save_paused_keys(updated_paused_df):
        await update.message.reply_text(f"❌ Error saving to {PAUSED_CSV_FILE}. Pause failed.")
        return

    # 5. Remove from active list by name
    if not remove_active_user_by_name(name_to_pause):
        await update.message.reply_text(f"⚠️ Warning: Failed remove `{name_to_pause}` from active list, but pause data saved. Check manually.")
        logger.error(f"CRITICAL: Failed remove {name_to_pause} from {CSV_FILE} after saving to {PAUSED_CSV_FILE}.")
        return

    # 6. Confirm pause
    remaining_time_str = format_seconds(remaining_seconds)
    await update.message.reply_text(
        f"⏸️ Key for user `{name_to_pause}` (HWID: `{hwid}`) paused.\n"
        f"Remaining time saved: `{remaining_time_str}`."
    )
    logger.info(f"Admin {user_id} paused user {name_to_pause} (HWID {hwid}) with {remaining_seconds}s left.")

async def unpause_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /unpause command:
    Usage: /unpause <username>
    Unpauses the key (case-insensitive), restores time, and provides a new key.
    """
    user_id = update.message.from_user.id
    if user_id not in ADMIN_USER_IDS:
        await update.message.reply_text("❌ You do not have permission.")
        return

    args = context.args
    if len(args) != 1:
        await update.message.reply_text("⚠️ Usage: /unpause <username>")
        return

    # --- Unpause by name (lowercase) ---
    name_to_unpause = args[0].lower()
    current_time = int(time.time())

    # 1. Find the user in the paused keys file by name
    paused_user_data = find_paused_user_by_name(name_to_unpause)

    if paused_user_data is None:
        if find_user_by_name(name_to_unpause) is not None:
             await update.message.reply_text(f"ℹ️ User `{name_to_unpause}` is already active.")
        else:
             await update.message.reply_text(f"❌ Error: User `{name_to_unpause}` not found in paused list.")
        return

    # 2. Extract details
    try:
        # Name is already lowercase from find_paused_user_by_name
        hwid = str(paused_user_data['hwid']) # Get HWID from paused data
        remaining_seconds = int(paused_user_data['remaining_seconds'])
    except (KeyError, ValueError) as e:
         await update.message.reply_text(f"❌ Error reading paused data for `{name_to_unpause}`. Corrupted? {e}")
         logger.error(f"Data error for name {name_to_unpause} in {PAUSED_CSV_FILE}: {e}")
         return

    if remaining_seconds <= 0:
         await update.message.reply_text(f"❌ Error: Paused key for `{name_to_unpause}` has no time left.")
         # Optionally remove from paused list here
         # remove_paused_user_by_name(name_to_unpause)
         return

    # 3. Calculate new expiration time
    new_expiration_time = current_time + remaining_seconds

    # 4. Add/Update in active list (using save_key_details handles add/update)
    if not save_key_details(name_to_unpause, hwid, new_expiration_time): # Use retrieved HWID
        await update.message.reply_text(f"❌ Error saving key details to {CSV_FILE}. Unpause failed.")
        return

    # 5. Remove from paused list by name
    if not remove_paused_user_by_name(name_to_unpause):
        await update.message.reply_text(f"⚠️ Warning: Failed remove `{name_to_unpause}` from paused list, but key likely reactivated. Check manually.")
        logger.error(f"CRITICAL: Failed remove {name_to_unpause} from {PAUSED_CSV_FILE} after saving to {CSV_FILE}.")
        return

    # --- 6. Generate the new key ---
    new_key = generate_key(new_expiration_time, hwid, name_to_unpause)

    # 7. Confirm unpause and provide key
    try:
        new_expiration_dt = datetime.datetime.fromtimestamp(new_expiration_time)
        local_tz_name = datetime.datetime.now().astimezone().tzname()
        new_expiration_date_str = new_expiration_dt.strftime(f'%Y-%m-%d %H:%M:%S {local_tz_name or "Local"}')
    except Exception:
        new_expiration_date_str = f"Timestamp {new_expiration_time}"

    remaining_time_str = format_seconds(remaining_seconds)

    await update.message.reply_text(
        f"▶️ User `{name_to_unpause}` (HWID: `{hwid}`) unpaused.\n"
        f"Remaining time applied: `{remaining_time_str}`.\n"
        f"New expiration: `{new_expiration_date_str}`.\n\n"
        f"🔑 New Key:\n`{new_key}`", # Include the new key
        parse_mode='Markdown'
    )
    logger.info(f"Admin {user_id} unpaused user {name_to_unpause} (HWID {hwid}). New expiry: {new_expiration_time}")

async def balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /balance  —  Shows sub-admin their remaining wallet balance.
    """
    user_id = update.message.from_user.id
    if user_id not in SUB_ADMIN_USER_IDS:
        await update.message.reply_text("❌ You do not have permission.")
        return

    secs = get_subadmin_balance(user_id)
    await update.message.reply_text(f"💰 Your wallet balance: {format_seconds(secs)}")

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Exception while handling an update:", exc_info=context.error)

def main() -> None:
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("gen", generate_key_command))
    app.add_handler(CommandHandler("addwallet", addwallet_command))
    app.add_handler(CommandHandler("get", get_csv_command))
    app.add_handler(CommandHandler("pause", pause_key_command))
    app.add_handler(CommandHandler("unpause", unpause_key_command))
    app.add_handler(CommandHandler("check", check_key_command))
    app.add_handler(MessageHandler(filters.Document.ALL & filters.CaptionRegex(r'^/setcsv$'), set_csv_handler))
    app.add_handler(CommandHandler("balance", balance_command))
    app.add_error_handler(error_handler)
    app.run_polling(poll_interval=3, timeout=20)

if __name__ == '__main__':
    main()
