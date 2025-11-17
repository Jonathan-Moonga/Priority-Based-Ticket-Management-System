import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import queue
import csv
import os
from datetime import datetime
import json
import random
import string
import re
import hashlib
import secrets

class TicketingSystem:
    def __init__(self):
        # Initialize queues
        self.vip_queue = queue.Queue()
        self.regular_queue = queue.Queue()
        
        # Ticket availability
        self.vip_available = 50
        self.regular_available = 100
        
        # Pricing (can be modified by admin)
        self.vip_price = 100.0
        self.regular_price = 50.0
        self.tax_rate = 0.10  # 10% tax
        
        # Credential storage files
        self.users_file = "users.json"
        self.admins_file = "admins.json"

        # Load or initialize credential stores
        self.admins = self._load_or_create_admins()
        self.users = self._load_credentials(self.users_file)

        # Store all transactions with their receipt IDs
        self.transactions = {}

        # Transaction log file
        self.log_file = "transactions.csv"
        self._initialize_log_file()
        
    def _initialize_log_file(self):
        """Create CSV file if it doesn't exist"""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Receipt ID', 'Timestamp', 'User', 'Ticket Type', 'Status', 'Price', 'Quantity', 'Processed By', 'Processed At'])
        
        # Load existing transactions
        self._load_transactions()
    
    def _load_transactions(self):
        """Load existing transactions from CSV"""
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Only load rows that have a Receipt ID (skip old format)
                    if row and 'Receipt ID' in row and row['Receipt ID']:
                        self.transactions[row['Receipt ID']] = row
    
    def _generate_receipt_id(self):
        """Generate unique receipt ID"""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    
    def validate_password(self, password):
        """
        Validate password requirements:
        - 8-15 characters
        - At least 1 number
        - At least 1 special character
        - At least 1 alphabetic character
        
        Returns: (is_valid, error_message)
        """
        if len(password) < 8 or len(password) > 15:
            return False, "Password must be between 8-15 characters long"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least 1 number"
        
        if not re.search(r'[a-zA-Z]', password):
            return False, "Password must contain at least 1 alphabetic character"
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            return False, "Password must contain at least 1 special character (!@#$%^&*()_+-=[]{}';:\",.<>?/\\|`~)"
        
        return True, "Password is valid"

    # --- Credential storage helpers ---
    def _hash_password(self, password):
        """Hash a password using PBKDF2-HMAC-SHA256 and return dict with salt+hash (hex)."""
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
        return {'salt': salt.hex(), 'hash': dk.hex()}

    def _verify_password(self, stored, password):
        """Verify a password against stored dict {'salt':..., 'hash':...}."""
        try:
            salt = bytes.fromhex(stored['salt'])
            expected = stored['hash']
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
            return dk.hex() == expected
        except Exception:
            return False

    def _load_credentials(self, path):
        """Load credential dict from JSON file. Returns {username: {salt,hash}} or {}."""
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_credentials(self, path, creds):
        """Save credential dict to JSON file."""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(creds, f, indent=2)

    def _load_or_create_admins(self):
        """Load admins from file or create file from default hard-coded admin."""
        default_admins = {"admin": "admin123"}
        creds = self._load_credentials(self.admins_file)
        if not creds:
            # create hashed admin file from defaults
            creds = {}
            for u, p in default_admins.items():
                creds[u] = self._hash_password(p)
            try:
                self._save_credentials(self.admins_file, creds)
            except Exception:
                pass
        return creds

    def add_user(self, username, password):
        """Add a new user with hashed password and persist."""
        self.users[username] = self._hash_password(password)
        try:
            self._save_credentials(self.users_file, self.users)
        except Exception:
            pass

    def add_admin(self, username, password):
        """Add a new admin with hashed password and persist."""
        self.admins[username] = self._hash_password(password)
        try:
            self._save_credentials(self.admins_file, self.admins)
        except Exception:
            pass

    def verify_user(self, username, password):
        """Verify a user's password. Returns True/False."""
        if username not in self.users:
            return False
        return self._verify_password(self.users[username], password)

    def verify_admin(self, username, password):
        """Verify an admin's password. Returns True/False."""
        if username not in self.admins:
            return False
        return self._verify_password(self.admins[username], password)
    
    def log_transaction(self, receipt_id, user, ticket_type, status, price=0, processed_by="", processed_at="", quantity=1):
        """Log or update transaction to CSV"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Update in-memory store
        self.transactions[receipt_id] = {
            'Receipt ID': receipt_id,
            'Timestamp': timestamp,
            'User': user,
            'Ticket Type': ticket_type,
            'Status': status,
            'Price': price,
            'Quantity': quantity,
            'Processed By': processed_by,
            'Processed At': processed_at
        }
        
        # Rewrite entire CSV
        with open(self.log_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Receipt ID', 'Timestamp', 'User', 'Ticket Type', 'Status', 'Price', 'Quantity', 'Processed By', 'Processed At'])
            for trans in self.transactions.values():
                writer.writerow([trans['Receipt ID'], trans['Timestamp'], trans['User'], 
                               trans['Ticket Type'], trans['Status'], trans['Price'],
                               trans.get('Quantity', 1),
                               trans['Processed By'], trans['Processed At']])
    
    def add_to_queue(self, user, ticket_type, quantity=1):
        """Add user to appropriate queue"""
        receipt_id = self._generate_receipt_id()
        price = self.vip_price if ticket_type == "VIP" else self.regular_price
        total_price = price * quantity
        
        if ticket_type == "VIP":
            self.vip_queue.put((user, ticket_type, receipt_id, quantity))
        else:
            self.regular_queue.put((user, ticket_type, receipt_id, quantity))
        
        self.log_transaction(receipt_id, user, ticket_type, "PENDING", total_price, quantity=quantity)
        return receipt_id
    
    def get_pending_requests(self):
        """Get all pending requests from both queues"""
        pending = []
        
        # Get VIP queue items (without removing)
        temp_vip = []
        while not self.vip_queue.empty():
            item = self.vip_queue.get()
            temp_vip.append(item)
            pending.append(item)
        
        # Restore VIP queue
        for item in temp_vip:
            self.vip_queue.put(item)
        
        # Get Regular queue items (without removing)
        temp_regular = []
        while not self.regular_queue.empty():
            item = self.regular_queue.get()
            temp_regular.append(item)
            pending.append(item)
        
        # Restore Regular queue
        for item in temp_regular:
            self.regular_queue.put(item)
        
        return pending
    
    def approve_ticket(self, receipt_id, admin_name):
        """Approve a specific ticket request"""
        # Find and remove from queue
        result = self._remove_from_queue(receipt_id)
        user, ticket_type = result[0], result[1]
        quantity = result[2] if len(result) > 2 else 1
        
        if not user:
            return "Ticket not found in queue"
        
        if ticket_type == "VIP":
            if self.vip_available >= quantity:
                self.vip_available -= quantity
                base_price = self.vip_price * quantity
                total_price = base_price * (1 + self.tax_rate)
                processed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.log_transaction(receipt_id, user, ticket_type, "APPROVED", total_price, admin_name, processed_at, quantity=quantity)
                return f"✓ {quantity} VIP ticket(s) approved for {user}"
            else:
                # Ticket sold out - reject it
                processed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.log_transaction(receipt_id, user, ticket_type, "REJECTED - SOLD OUT", 0, admin_name, processed_at, quantity=quantity)
                return f"✗ Not enough VIP tickets available (need {quantity}, have {self.vip_available}) - request rejected"
        else:
            if self.regular_available >= quantity:
                self.regular_available -= quantity
                base_price = self.regular_price * quantity
                total_price = base_price * (1 + self.tax_rate)
                processed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.log_transaction(receipt_id, user, ticket_type, "APPROVED", total_price, admin_name, processed_at, quantity=quantity)
                return f"✓ {quantity} Regular ticket(s) approved for {user}"
            else:
                processed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.log_transaction(receipt_id, user, ticket_type, "REJECTED - SOLD OUT", 0, admin_name, processed_at, quantity=quantity)
                return f"✗ Not enough Regular tickets available (need {quantity}, have {self.regular_available}) - request rejected"
    
    def reject_ticket(self, receipt_id, admin_name):
        """Reject a specific ticket request"""
        result = self._remove_from_queue(receipt_id)
        user, ticket_type = result[0], result[1]
        quantity = result[2] if len(result) > 2 else 1
        
        if not user:
            return "Ticket not found in queue"
        
        processed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_transaction(receipt_id, user, ticket_type, "REJECTED BY ADMIN", 0, admin_name, processed_at, quantity=quantity)
        return f"✗ Ticket request rejected for {user}"
    
    def cancel_ticket(self, receipt_id, user):
        """Cancel a ticket and free up availability"""
        if receipt_id not in self.transactions:
            return False, "Ticket not found"
        
        trans = self.transactions[receipt_id]
        quantity = trans.get('Quantity', 1)
        
        # Check if user owns this ticket
        if trans['User'] != user:
            return False, "This ticket doesn't belong to you"
        
        # Check if already processed
        if trans['Status'] == 'CANCELLED':
            return False, "Ticket already cancelled"
        
        if trans['Status'] == 'PENDING':
            # Remove from queue
            self._remove_from_queue(receipt_id)
            self.log_transaction(receipt_id, user, trans['Ticket Type'], "CANCELLED", 0, user, 
                               datetime.now().strftime('%Y-%m-%d %H:%M:%S'), quantity=quantity)
            return True, "Ticket request cancelled"
        
        elif trans['Status'] == 'APPROVED':
            # Free up the tickets
            if trans['Ticket Type'] == 'VIP':
                self.vip_available += quantity
            else:
                self.regular_available += quantity
            
            self.log_transaction(receipt_id, user, trans['Ticket Type'], "CANCELLED", 0, user,
                               datetime.now().strftime('%Y-%m-%d %H:%M:%S'), quantity=quantity)
            return True, f"{quantity} ticket(s) cancelled and spots freed up"
        
        else:
            return False, "Cannot cancel this ticket"
    
    def _remove_from_queue(self, receipt_id):
        """Remove specific item from queue by receipt ID"""
        # Check VIP queue
        temp_vip = []
        found_user = None
        found_type = None
        found_quantity = 1
        
        while not self.vip_queue.empty():
            item = self.vip_queue.get()
            # Handle both old format (3 items) and new format (4 items with quantity)
            if len(item) == 4:
                user, ticket_type, rid, quantity = item
            else:
                user, ticket_type, rid = item
                quantity = 1
            
            if rid == receipt_id:
                found_user = user
                found_type = ticket_type
                found_quantity = quantity
            else:
                self.vip_queue.put(item)
        
        if found_user:
            return found_user, found_type, found_quantity
        
        # Check Regular queue
        temp_regular = []
        while not self.regular_queue.empty():
            item = self.regular_queue.get()
            # Handle both old format (3 items) and new format (4 items with quantity)
            if len(item) == 4:
                user, ticket_type, rid, quantity = item
            else:
                user, ticket_type, rid = item
                quantity = 1
            
            if rid == receipt_id:
                found_user = user
                found_type = ticket_type
                found_quantity = quantity
            else:
                self.regular_queue.put(item)
        
        return found_user, found_type, found_quantity
    
    def get_queue_status(self):
        """Get current queue status"""
        return {
            'vip_queue': self.vip_queue.qsize(),
            'regular_queue': self.regular_queue.qsize(),
            'vip_available': self.vip_available,
            'regular_available': self.regular_available
        }
    
    def get_user_tickets(self, username):
        """Get all tickets for a specific user"""
        return [trans for trans in self.transactions.values() if trans['User'] == username]


class TicketingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Event Ticketing System")
        self.root.geometry("950x700")
        self.root.configure(bg='#2c3e50')
        
        self.system = TicketingSystem()
        self.current_user = None
        self.is_admin = False
        
        self.show_login_screen()
    
    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Display login/registration screen"""
        self.clear_window()
        
        # Main container frame
        main_frame = tk.Frame(self.root, bg='#34495e')
        main_frame.pack(fill='both', expand=True)
        
        # Left panel - Login form
        left_frame = tk.Frame(main_frame, bg='#34495e', padx=40, pady=40)
        left_frame.pack(side='left', fill='both', expand=True)
        
        frame = tk.Frame(left_frame, bg='#34495e')
        frame.pack()
        
        tk.Label(frame, text="🎟️ Event Ticketing System", font=('Arial', 24, 'bold'),
                bg='#34495e', fg='white').grid(row=0, column=0, columnspan=2, pady=20)
        
        tk.Label(frame, text="Username:", font=('Arial', 12),
                bg='#34495e', fg='white').grid(row=1, column=0, sticky='e', padx=10, pady=10)
        self.username_entry = tk.Entry(frame, font=('Arial', 12), width=25)
        self.username_entry.grid(row=1, column=1, pady=10)
        
        tk.Label(frame, text="Password:", font=('Arial', 12),
                bg='#34495e', fg='white').grid(row=2, column=0, sticky='e', padx=10, pady=10)
        self.password_entry = tk.Entry(frame, font=('Arial', 12), width=25, show='*')
        self.password_entry.grid(row=2, column=1, pady=10)
        
        btn_frame = tk.Frame(frame, bg='#34495e')
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        tk.Button(btn_frame, text="User Login", command=self.user_login,
                 font=('Arial', 12), bg='#3498db', fg='white', width=12, pady=5).pack(side='left', padx=5)
        tk.Button(btn_frame, text="Admin Login", command=self.admin_login,
                 font=('Arial', 12), bg='#e74c3c', fg='white', width=12, pady=5).pack(side='left', padx=5)
        
        tk.Button(frame, text="Create User Account", command=self.show_registration,
                 font=('Arial', 11), bg='#27ae60', fg='white', width=28, pady=5).grid(row=4, column=0, columnspan=2, pady=10)
        
        # Right panel - Password requirements guide
        right_frame = tk.Frame(main_frame, bg='#2c3e50', padx=30, pady=30)
        right_frame.pack(side='right', fill='both', expand=True)
        
        # Title
        tk.Label(right_frame, text="🔐 Password Requirements", font=('Arial', 16, 'bold'),
                bg='#2c3e50', fg='#f39c12').pack(pady=(0, 20))
        
        # Requirements list
        requirements = [
            ("✓", "8-15 characters long", "#3498db"),
            ("✓", "At least 1 number (0-9)", "#3498db"),
            ("✓", "At least 1 letter (a-z, A-Z)", "#3498db"),
            ("✓", "At least 1 special character", "#3498db"),
        ]
        
        for symbol, req_text, color in requirements:
            req_frame = tk.Frame(right_frame, bg='#2c3e50')
            req_frame.pack(fill='x', pady=8, anchor='w')
            
            tk.Label(req_frame, text=symbol, font=('Arial', 14, 'bold'),
                    bg='#2c3e50', fg=color, width=3).pack(side='left')
            tk.Label(req_frame, text=req_text, font=('Arial', 11),
                    bg='#2c3e50', fg='white').pack(side='left', padx=10)
        
        # Separator
        tk.Label(right_frame, text="─" * 35, bg='#2c3e50', fg='#7f8c8d').pack(pady=15)
        
        # Examples
        tk.Label(right_frame, text="Valid Examples:", font=('Arial', 12, 'bold'),
                bg='#2c3e50', fg='#2ecc71').pack(pady=(10, 8), anchor='w')
        
        examples = [
            "MyPass123!",
            "Admin@2024",
            "Test#Pass99",
            "Secure$Pwd1"
        ]
        
        for example in examples:
            ex_frame = tk.Frame(right_frame, bg='#2c3e50')
            ex_frame.pack(fill='x', pady=4, anchor='w')
            tk.Label(ex_frame, text="• " + example, font=('Courier', 10),
                    bg='#2c3e50', fg='#2ecc71').pack(anchor='w')
        
        # Special characters info
        tk.Label(right_frame, text="─" * 35, bg='#2c3e50', fg='#7f8c8d').pack(pady=15)
        tk.Label(right_frame, text="Special Characters:", font=('Arial', 11, 'bold'),
                bg='#2c3e50', fg='#e74c3c').pack(pady=(5, 8), anchor='w')
        tk.Label(right_frame, text="!@#$%^&*()_+-=[]{}';:\",.<>?/\\|`~",
                font=('Courier', 9), bg='#2c3e50', fg='#ecf0f1',
                wraplength=200, justify='left').pack(anchor='w')
    
    def show_registration(self):
        """Show user registration form"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Missing Information", "Please enter both username and password")
            return
        
        # Validate password
        is_valid, message = self.system.validate_password(password)
        if not is_valid:
            # Create detailed error message for wrong format
            error_details = message + "\n\n" + \
                "Password Requirements:\n" + \
                "• 8-15 characters long\n" + \
                "• At least 1 number (0-9)\n" + \
                "• At least 1 letter (a-z, A-Z)\n" + \
                "• At least 1 special character (!@#$%^&*()_+-=[]{}';:\",.<>?/\\|`~)\n\n" + \
                "Valid Example: MyPass123!"
            messagebox.showerror("Invalid Password Format", error_details)
            return
        
        if username in self.system.users or username in self.system.admins:
            messagebox.showerror("Username Exists", "This username is already taken. Please choose a different one.")
            return

        # Store hashed password and persist
        self.system.add_user(username, password)
        messagebox.showinfo("Success", f"Account '{username}' created successfully!\nYou can now login with your credentials.")
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
    
    def user_login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if self.system.verify_user(username, password):
            self.current_user = username
            self.is_admin = False
            self.show_user_dashboard()
        else:
            messagebox.showerror("Error", "Invalid credentials")
    
    def admin_login(self):
        """Handle admin login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if self.system.verify_admin(username, password):
            self.current_user = username
            self.is_admin = True
            self.show_admin_dashboard()
        else:
            messagebox.showerror("Error", "Invalid admin credentials")
    
    def show_user_dashboard(self):
        """Display user dashboard"""
        self.clear_window()
        
        # Header
        header = tk.Frame(self.root, bg='#2c3e50', pady=10)
        header.pack(fill='x')
        
        tk.Label(header, text=f"Welcome, {self.current_user}!", font=('Arial', 18, 'bold'),
                bg='#2c3e50', fg='white').pack()
        
        btn_frame = tk.Frame(header, bg='#2c3e50')
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Refresh", command=self.show_user_dashboard,
                 font=('Arial', 10), bg='#3498db', fg='white').pack(side='left', padx=5)
        tk.Button(btn_frame, text="Logout", command=self.show_login_screen,
                 font=('Arial', 10), bg='#e74c3c', fg='white').pack(side='left', padx=5)
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#34495e')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Left panel
        left_panel = tk.Frame(main_frame, bg='#34495e')
        left_panel.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Ticket availability
        status = self.system.get_queue_status()
        
        avail_frame = tk.LabelFrame(left_panel, text="Ticket Availability", font=('Arial', 14, 'bold'),
                                    bg='#34495e', fg='white', padx=20, pady=15)
        avail_frame.pack(fill='x', pady=10)
        
        tk.Label(avail_frame, text=f"🌟 VIP Tickets Available: {status['vip_available']}",
                font=('Arial', 12), bg='#34495e', fg='#f39c12').pack(anchor='w', pady=5)
        tk.Label(avail_frame, text=f"🎫 Regular Tickets Available: {status['regular_available']}",
                font=('Arial', 12), bg='#34495e', fg='#3498db').pack(anchor='w', pady=5)
        
        # Pricing info
        price_frame = tk.LabelFrame(left_panel, text="Pricing", font=('Arial', 14, 'bold'),
                                    bg='#34495e', fg='white', padx=20, pady=15)
        price_frame.pack(fill='x', pady=10)
        
        vip_total = self.system.vip_price * (1 + self.system.tax_rate)
        regular_total = self.system.regular_price * (1 + self.system.tax_rate)
        
        tk.Label(price_frame, text=f"VIP: ${self.system.vip_price:.2f} + tax = ${vip_total:.2f}",
                font=('Arial', 11), bg='#34495e', fg='white').pack(anchor='w', pady=3)
        tk.Label(price_frame, text=f"Regular: ${self.system.regular_price:.2f} + tax = ${regular_total:.2f}",
                font=('Arial', 11), bg='#34495e', fg='white').pack(anchor='w', pady=3)
        
        # Purchase section
        purchase_frame = tk.LabelFrame(left_panel, text="Purchase Ticket", font=('Arial', 14, 'bold'),
                                       bg='#34495e', fg='white', padx=20, pady=15)
        purchase_frame.pack(fill='x', pady=10)
        
        tk.Label(purchase_frame, text="Select Ticket Type:", font=('Arial', 11),
                bg='#34495e', fg='white').pack(anchor='w', pady=5)
        
        self.ticket_type_var = tk.StringVar(value="Regular")
        tk.Radiobutton(purchase_frame, text="VIP Ticket", variable=self.ticket_type_var,
                      value="VIP", font=('Arial', 11), bg='#34495e', fg='white',
                      selectcolor='#2c3e50').pack(anchor='w')
        tk.Radiobutton(purchase_frame, text="Regular Ticket", variable=self.ticket_type_var,
                      value="Regular", font=('Arial', 11), bg='#34495e', fg='white',
                      selectcolor='#2c3e50').pack(anchor='w')
        
        # Quantity input
        qty_frame = tk.Frame(purchase_frame, bg='#34495e')
        qty_frame.pack(anchor='w', pady=(10, 5))
        
        tk.Label(qty_frame, text="Quantity:", font=('Arial', 11),
                bg='#34495e', fg='white').pack(side='left', padx=(0, 10))
        
        self.quantity_var = tk.StringVar(value="1")
        quantity_spinbox = tk.Spinbox(qty_frame, from_=1, to=100, textvariable=self.quantity_var,
                                     font=('Arial', 11), width=5, bg='white', fg='#2c3e50',
                                     justify='center')
        quantity_spinbox.pack(side='left')
        
        tk.Button(purchase_frame, text="Request Ticket(s)", command=self.request_ticket,
                 font=('Arial', 12, 'bold'), bg='#27ae60', fg='white', pady=8).pack(pady=10)
        
        # Right panel - My Tickets
        right_panel = tk.Frame(main_frame, bg='#34495e')
        right_panel.pack(side='right', fill='both', expand=True)
        
        tickets_frame = tk.LabelFrame(right_panel, text="My Tickets (Double-click to view receipt)",
                                      font=('Arial', 14, 'bold'), bg='#34495e', fg='white', padx=10, pady=10)
        tickets_frame.pack(fill='both', expand=True)
        
        # Create treeview for tickets
        tree_frame = tk.Frame(tickets_frame, bg='#34495e')
        tree_frame.pack(fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.tickets_tree = ttk.Treeview(tree_frame, columns=('Receipt', 'Type', 'Status'),
                                         show='headings', yscrollcommand=scrollbar.set, height=15)
        self.tickets_tree.pack(fill='both', expand=True)
        scrollbar.config(command=self.tickets_tree.yview)
        
        self.tickets_tree.heading('Receipt', text='Receipt ID')
        self.tickets_tree.heading('Type', text='Type')
        self.tickets_tree.heading('Status', text='Status')
        
        self.tickets_tree.column('Receipt', width=100)
        self.tickets_tree.column('Type', width=80)
        self.tickets_tree.column('Status', width=120)
        
        # Bind double-click
        self.tickets_tree.bind('<Double-1>', self.show_receipt)
        
        # Load user tickets
        self.load_user_tickets()
        
        # Cancel button
        tk.Button(tickets_frame, text="Cancel Selected Ticket", command=self.cancel_selected_ticket,
                 font=('Arial', 11), bg='#e67e22', fg='white', pady=6).pack(pady=10)
    
    def load_user_tickets(self):
        """Load tickets for current user"""
        self.tickets_tree.delete(*self.tickets_tree.get_children())
        
        tickets = self.system.get_user_tickets(self.current_user)
        for ticket in tickets:
            self.tickets_tree.insert('', 'end', values=(
                ticket['Receipt ID'],
                ticket['Ticket Type'],
                ticket['Status']
            ), tags=(ticket['Status'],))
        
        # Configure tags for colors
        self.tickets_tree.tag_configure('APPROVED', foreground='green')
        self.tickets_tree.tag_configure('PENDING', foreground='orange')
        self.tickets_tree.tag_configure('REJECTED BY ADMIN', foreground='red')
        self.tickets_tree.tag_configure('REJECTED - SOLD OUT', foreground='red')
        self.tickets_tree.tag_configure('CANCELLED', foreground='gray')
    
    def show_receipt(self, event):
        """Show receipt for selected ticket"""
        selection = self.tickets_tree.selection()
        if not selection:
            return
        
        item = self.tickets_tree.item(selection[0])
        receipt_id = item['values'][0]
        
        if receipt_id in self.system.transactions:
            trans = self.system.transactions[receipt_id]
            self.display_receipt(trans)
    
    def display_receipt(self, trans):
        """Display formatted receipt"""
        receipt_window = tk.Toplevel(self.root)
        receipt_window.title("Ticket Receipt")
        receipt_window.geometry("450x500")
        receipt_window.configure(bg='white')
        
        # Header
        header_frame = tk.Frame(receipt_window, bg='#2c3e50', pady=15)
        header_frame.pack(fill='x')
        
        tk.Label(header_frame, text="🎟️ TICKET RECEIPT", font=('Arial', 20, 'bold'),
                bg='#2c3e50', fg='white').pack()
        
        # Receipt content
        content_frame = tk.Frame(receipt_window, bg='white', padx=30, pady=20)
        content_frame.pack(fill='both', expand=True)
        
        # Create receipt text
        receipt_type = f"{trans['Ticket Type']} RECEIPT"
        tk.Label(content_frame, text=receipt_type, font=('Arial', 16, 'bold'),
                bg='white', fg='#2c3e50').pack(pady=(0, 20))
        
        # Receipt details in table format
        details = [
            ("Receipt ID:", trans['Receipt ID']),
            ("User:", trans['User']),
            ("Ticket Type:", trans['Ticket Type']),
            ("Base Price:", f"${float(trans['Price']) / (1 + self.system.tax_rate):.2f}" if trans['Status'] == 'APPROVED' else "$0.00"),
            ("Tax ({:.0f}%):".format(self.system.tax_rate * 100), f"${float(trans['Price']) - (float(trans['Price']) / (1 + self.system.tax_rate)):.2f}" if trans['Status'] == 'APPROVED' else "$0.00"),
            ("", ""),
            ("Total Price:", f"${float(trans['Price']):.2f}" if trans['Status'] == 'APPROVED' else "$0.00"),
            ("", ""),
            ("Status:", trans['Status']),
            ("Requested At:", trans['Timestamp']),
        ]
        
        if trans['Processed By']:
            details.append(("Processed By:", trans['Processed By']))
        if trans['Processed At']:
            details.append(("Processed At:", trans['Processed At']))
        
        # Display details
        for label, value in details:
            row_frame = tk.Frame(content_frame, bg='white')
            row_frame.pack(fill='x', pady=3)
            
            if label == "":
                tk.Label(row_frame, text="─" * 50, bg='white', fg='#bdc3c7').pack()
            else:
                tk.Label(row_frame, text=label, font=('Arial', 11, 'bold'),
                        bg='white', fg='#34495e', width=15, anchor='w').pack(side='left')
                
                color = '#27ae60' if trans['Status'] == 'APPROVED' else '#e74c3c' if 'REJECT' in trans['Status'] else '#f39c12'
                font_style = ('Arial', 11, 'bold') if label == "Total Price:" or label == "Status:" else ('Arial', 11)
                
                tk.Label(row_frame, text=value, font=font_style,
                        bg='white', fg=color if label == "Status:" or label == "Total Price:" else '#2c3e50',
                        anchor='w').pack(side='left')
        
        # Footer
        footer_frame = tk.Frame(receipt_window, bg='#ecf0f1', pady=15)
        footer_frame.pack(fill='x', side='bottom')
        
        tk.Label(footer_frame, text="THANK YOU FOR YOUR BUSINESS!", font=('Arial', 12, 'bold'),
                bg='#ecf0f1', fg='#2c3e50').pack()
        
        tk.Button(footer_frame, text="Close", command=receipt_window.destroy,
                 font=('Arial', 11), bg='#3498db', fg='white', padx=30, pady=8).pack(pady=10)
    
    def cancel_selected_ticket(self):
        """Cancel selected ticket"""
        selection = self.tickets_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a ticket to cancel")
            return
        
        item = self.tickets_tree.item(selection[0])
        receipt_id = item['values'][0]
        
        if messagebox.askyesno("Confirm", "Are you sure you want to cancel this ticket?"):
            success, message = self.system.cancel_ticket(receipt_id, self.current_user)
            if success:
                messagebox.showinfo("Success", message)
                self.show_user_dashboard()
            else:
                messagebox.showerror("Error", message)
    
    def request_ticket(self):
        """Handle ticket request"""
        ticket_type = self.ticket_type_var.get()
        try:
            quantity = int(self.quantity_var.get())
            if quantity < 1 or quantity > 100:
                messagebox.showerror("Invalid Quantity", "Please enter a quantity between 1 and 100")
                return
        except ValueError:
            messagebox.showerror("Invalid Quantity", "Please enter a valid number for quantity")
            return
        
        # Check availability before adding to queue
        status = self.system.get_queue_status()
        available = status['vip_available'] if ticket_type == 'VIP' else status['regular_available']
        
        if quantity > available:
            messagebox.showwarning("Insufficient Tickets", 
                                 f"Only {available} {ticket_type} ticket(s) available.\nYou requested {quantity}.")
            return
        
        receipt_id = self.system.add_to_queue(self.current_user, ticket_type, quantity)
        messagebox.showinfo("Success", 
                          f"Your request for {quantity} {ticket_type} ticket(s) has been added to the queue!\n\nReceipt ID: {receipt_id}")
        self.show_user_dashboard()
    
    def show_admin_dashboard(self):
        """Display admin dashboard"""
        self.clear_window()
        
        # Header
        header = tk.Frame(self.root, bg='#2c3e50', pady=10)
        header.pack(fill='x')
        
        tk.Label(header, text=f"Admin Panel - {self.current_user}", font=('Arial', 18, 'bold'),
                bg='#2c3e50', fg='white').pack()
        
        btn_frame = tk.Frame(header, bg='#2c3e50')
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Refresh", command=self.show_admin_dashboard,
                 font=('Arial', 10), bg='#3498db', fg='white').pack(side='left', padx=5)
        tk.Button(btn_frame, text="Logout", command=self.show_login_screen,
                 font=('Arial', 10), bg='#e74c3c', fg='white').pack(side='left', padx=5)
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#34495e')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_frame, bg='#34495e', width=300)
        left_panel.pack(side='left', fill='both', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Dashboard stats
        stats_frame = tk.LabelFrame(left_panel, text="Dashboard", font=('Arial', 14, 'bold'),
                                    bg='#34495e', fg='white', padx=15, pady=10)
        stats_frame.pack(fill='x', pady=10)
        
        status = self.system.get_queue_status()
        
        tk.Label(stats_frame, text=f"VIP Available: {status['vip_available']}",
                font=('Arial', 11), bg='#34495e', fg='#f39c12').pack(anchor='w', pady=2)
        tk.Label(stats_frame, text=f"Regular Available: {status['regular_available']}",
                font=('Arial', 11), bg='#34495e', fg='#3498db').pack(anchor='w', pady=2)
        tk.Label(stats_frame, text=f"VIP Queue: {status['vip_queue']}",
                font=('Arial', 11), bg='#34495e', fg='white').pack(anchor='w', pady=2)
        tk.Label(stats_frame, text=f"Regular Queue: {status['regular_queue']}",
                font=('Arial', 11), bg='#34495e', fg='white').pack(anchor='w', pady=2)
        
        # Pricing controls
        pricing_frame = tk.LabelFrame(left_panel, text="Set Pricing", font=('Arial', 14, 'bold'),
                                      bg='#34495e', fg='white', padx=15, pady=10)
        pricing_frame.pack(fill='x', pady=10)
        
        tk.Label(pricing_frame, text="VIP Price ($):", bg='#34495e', fg='white', font=('Arial', 10)).pack(anchor='w')
        self.vip_price_entry = tk.Entry(pricing_frame, font=('Arial', 11))
        self.vip_price_entry.insert(0, str(self.system.vip_price))
        self.vip_price_entry.pack(fill='x', pady=3)
        
        tk.Label(pricing_frame, text="Regular Price ($):", bg='#34495e', fg='white', font=('Arial', 10)).pack(anchor='w', pady=(5,0))
        self.regular_price_entry = tk.Entry(pricing_frame, font=('Arial', 11))
        self.regular_price_entry.insert(0, str(self.system.regular_price))
        self.regular_price_entry.pack(fill='x', pady=3)
        
        tk.Label(pricing_frame, text="Tax Rate (%):", bg='#34495e', fg='white', font=('Arial', 10)).pack(anchor='w', pady=(5,0))
        self.tax_entry = tk.Entry(pricing_frame, font=('Arial', 11))
        self.tax_entry.insert(0, str(self.system.tax_rate * 100))
        self.tax_entry.pack(fill='x', pady=3)
        
        tk.Button(pricing_frame, text="Update Pricing", command=self.update_pricing,
                 font=('Arial', 10), bg='#e67e22', fg='white', pady=5).pack(fill='x', pady=(8,0))
        
        # Admin management
        admin_frame = tk.LabelFrame(left_panel, text="Admin Management", font=('Arial', 14, 'bold'),
                                    bg='#34495e', fg='white', padx=15, pady=10)
        admin_frame.pack(fill='x', pady=10)
        
        tk.Label(admin_frame, text="New Admin Username:", bg='#34495e', fg='white', font=('Arial', 10)).pack(anchor='w')
        self.new_admin_user = tk.Entry(admin_frame, font=('Arial', 11))
        self.new_admin_user.pack(fill='x', pady=3)
        
        tk.Label(admin_frame, text="Password:", bg='#34495e', fg='white', font=('Arial', 10)).pack(anchor='w', pady=(5,0))
        self.new_admin_pass = tk.Entry(admin_frame, font=('Arial', 11), show='*')
        self.new_admin_pass.pack(fill='x', pady=3)
        
        tk.Button(admin_frame, text="Create Admin", command=self.create_admin,
                 font=('Arial', 10), bg='#9b59b6', fg='white', pady=5).pack(fill='x', pady=(8,0))
        
        # Right panel - Tabbed interface for transactions
        right_panel = tk.Frame(main_frame, bg='#34495e')
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(right_panel)
        notebook.pack(fill='both', expand=True)
        
        # Tab 1: Pending Requests
        pending_tab = tk.Frame(notebook, bg='#34495e')
        notebook.add(pending_tab, text='Pending Requests')
        
        pending_frame = tk.Frame(pending_tab, bg='#34495e', padx=10, pady=10)
        pending_frame.pack(fill='both', expand=True)
        
        tk.Label(pending_frame, text="Pending Ticket Requests", font=('Arial', 14, 'bold'),
                bg='#34495e', fg='white').pack(pady=(0, 10))
        
        # Pending requests treeview
        pending_tree_frame = tk.Frame(pending_frame, bg='#34495e')
        pending_tree_frame.pack(fill='both', expand=True)
        
        pending_scroll = tk.Scrollbar(pending_tree_frame)
        pending_scroll.pack(side='right', fill='y')
        
        self.pending_tree = ttk.Treeview(pending_tree_frame, columns=('Receipt', 'User', 'Type', 'Qty'),
                                         show='headings', yscrollcommand=pending_scroll.set, height=15)
        self.pending_tree.pack(fill='both', expand=True)
        pending_scroll.config(command=self.pending_tree.yview)
        
        self.pending_tree.heading('Receipt', text='Receipt ID')
        self.pending_tree.heading('User', text='User')
        self.pending_tree.heading('Type', text='Type')
        self.pending_tree.heading('Qty', text='Qty')
        
        self.pending_tree.column('Receipt', width=100)
        self.pending_tree.column('User', width=100)
        self.pending_tree.column('Type', width=70)
        self.pending_tree.column('Qty', width=50)
        
        # Load pending requests
        self.load_pending_requests()
        
        # Action buttons
        btn_frame = tk.Frame(pending_frame, bg='#34495e')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="✓ Approve", command=self.approve_selected,
                 font=('Arial', 11, 'bold'), bg='#27ae60', fg='white', width=15, pady=6).pack(side='left', padx=5)
        tk.Button(btn_frame, text="✗ Reject", command=self.reject_selected,
                 font=('Arial', 11, 'bold'), bg='#e74c3c', fg='white', width=15, pady=6).pack(side='left', padx=5)
        
        # Tab 2: All Transactions
        all_tab = tk.Frame(notebook, bg='#34495e')
        notebook.add(all_tab, text='All Transactions')
        
        all_frame = tk.Frame(all_tab, bg='#34495e', padx=10, pady=10)
        all_frame.pack(fill='both', expand=True)
        
        tk.Label(all_frame, text="Transaction History", font=('Arial', 14, 'bold'),
                bg='#34495e', fg='white').pack(pady=(0, 10))
        
        # All transactions treeview (includes Quantity)
        all_tree_frame = tk.Frame(all_frame, bg='#34495e')
        all_tree_frame.pack(fill='both', expand=True)

        all_scroll = tk.Scrollbar(all_tree_frame)
        all_scroll.pack(side='right', fill='y')

        self.all_tree = ttk.Treeview(all_tree_frame, columns=('Receipt', 'User', 'Type', 'Qty', 'Status', 'Price'),
                                     show='headings', yscrollcommand=all_scroll.set, height=18)
        self.all_tree.pack(fill='both', expand=True)
        all_scroll.config(command=self.all_tree.yview)

        self.all_tree.heading('Receipt', text='Receipt ID')
        self.all_tree.heading('User', text='User')
        self.all_tree.heading('Type', text='Type')
        self.all_tree.heading('Qty', text='Qty')
        self.all_tree.heading('Status', text='Status')
        self.all_tree.heading('Price', text='Price')

        self.all_tree.column('Receipt', width=90)
        self.all_tree.column('User', width=90)
        self.all_tree.column('Type', width=60)
        self.all_tree.column('Qty', width=40)
        self.all_tree.column('Status', width=120)
        self.all_tree.column('Price', width=80)

        # Load all transactions
        self.load_all_transactions()
    
    def load_pending_requests(self):
        """Load pending ticket requests"""
        self.pending_tree.delete(*self.pending_tree.get_children())
        
        pending = self.system.get_pending_requests()
        for item in pending:
            # Support both old-format (user, type, rid) and new-format (user, type, rid, qty)
            if len(item) == 4:
                user, ticket_type, receipt_id, quantity = item
            else:
                user, ticket_type, receipt_id = item
                quantity = 1
            self.pending_tree.insert('', 'end', values=(receipt_id, user, ticket_type, quantity))
    
    def load_all_transactions(self):
        """Load all transactions"""
        self.all_tree.delete(*self.all_tree.get_children())
        
        for trans in self.system.transactions.values():
            price_display = f"${float(trans['Price']):.2f}" if trans['Price'] else "$0.00"
            quantity = trans.get('Quantity', 1)
            self.all_tree.insert('', 'end', values=(
                trans['Receipt ID'],
                trans['User'],
                trans['Ticket Type'],
                quantity,
                trans['Status'],
                price_display
            ), tags=(trans['Status'],))
        
        # Configure tags for colors
        self.all_tree.tag_configure('APPROVED', foreground='green')
        self.all_tree.tag_configure('PENDING', foreground='orange')
        self.all_tree.tag_configure('REJECTED BY ADMIN', foreground='red')
        self.all_tree.tag_configure('REJECTED - SOLD OUT', foreground='red')
        self.all_tree.tag_configure('CANCELLED', foreground='gray')
    
    def approve_selected(self):
        """Approve selected ticket request"""
        selection = self.pending_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a request to approve")
            return
        
        item = self.pending_tree.item(selection[0])
        receipt_id = item['values'][0]
        
        result = self.system.approve_ticket(receipt_id, self.current_user)
        messagebox.showinfo("Result", result)
        self.show_admin_dashboard()
    
    def reject_selected(self):
        """Reject selected ticket request"""
        selection = self.pending_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a request to reject")
            return
        
        item = self.pending_tree.item(selection[0])
        receipt_id = item['values'][0]
        
        if messagebox.askyesno("Confirm", "Are you sure you want to reject this request?"):
            result = self.system.reject_ticket(receipt_id, self.current_user)
            messagebox.showinfo("Result", result)
            self.show_admin_dashboard()
    
    def update_pricing(self):
        """Update pricing settings"""
        try:
            vip_price = float(self.vip_price_entry.get())
            regular_price = float(self.regular_price_entry.get())
            tax_rate = float(self.tax_entry.get()) / 100
            
            if vip_price < 0 or regular_price < 0 or tax_rate < 0:
                raise ValueError("Prices must be positive")
            
            self.system.vip_price = vip_price
            self.system.regular_price = regular_price
            self.system.tax_rate = tax_rate
            
            messagebox.showinfo("Success", "Pricing updated successfully!")
            self.show_admin_dashboard()
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
    
    def create_admin(self):
        """Create new admin account"""
        username = self.new_admin_user.get().strip()
        password = self.new_admin_pass.get().strip()
        
        if not username or not password:
            messagebox.showerror("Missing Information", "Please enter both username and password")
            return
        
        # Validate password
        is_valid, message = self.system.validate_password(password)
        if not is_valid:
            # Create detailed error message for wrong format
            error_details = message + "\n\n" + \
                "Password Requirements:\n" + \
                "• 8-15 characters long\n" + \
                "• At least 1 number (0-9)\n" + \
                "• At least 1 letter (a-z, A-Z)\n" + \
                "• At least 1 special character (!@#$%^&*()_+-=[]{}';:\",.<>?/\\|`~)\n\n" + \
                "Valid Example: Admin@2024"
            messagebox.showerror("Invalid Password Format", error_details)
            return
        
        if username in self.system.admins or username in self.system.users:
            messagebox.showerror("Username Exists", "This username is already taken. Please choose a different one.")
            return

        # Store hashed admin password and persist
        self.system.add_admin(username, password)
        messagebox.showinfo("Success", f"Admin account '{username}' created successfully!")
        self.new_admin_user.delete(0, tk.END)
        self.new_admin_pass.delete(0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = TicketingApp(root)
    root.mainloop()