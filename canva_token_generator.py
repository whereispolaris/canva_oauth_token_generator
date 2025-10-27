import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json
from datetime import datetime, timedelta
import webbrowser
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import secrets
import hashlib
import base64

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the authorization code from the callback
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        
        if 'code' in params:
            self.server.auth_code = params['code'][0]
            
            # Send success response to browser
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            success_html = """
            <html>
                <head><title>Authorization Successful</title></head>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h1 style="color: #00C4CC;">Authorization Successful!</h1>
                    <p>You can close this window and return to the app.</p>
                </body>
            </html>
            """
            self.wfile.write(success_html.encode())
        elif 'error' in params:
            self.server.auth_error = params['error'][0]
            
            # Send error response to browser
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            error_html = f"""
            <html>
                <head><title>Authorization Failed</title></head>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h1 style="color: #FF0000;">✗ Authorization Failed</h1>
                    <p>Error: {params.get('error_description', ['Unknown error'])[0]}</p>
                    <p>You can close this window and return to the app.</p>
                </body>
            </html>
            """
            self.wfile.write(error_html.encode())
    
    def log_message(self, format, *args):
        # Suppress logging
        pass

class CanvaOAuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Canva Connect API - OAuth Token Generator")
        self.root.geometry("800x750")
        self.root.resizable(False, False)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Canva Connect API - OAuth Flow", 
                                font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Client ID
        ttk.Label(main_frame, text="Client ID:", font=('Helvetica', 11)).grid(
            row=1, column=0, sticky=tk.W, pady=5)
        self.client_id_entry = ttk.Entry(main_frame, width=60)
        self.client_id_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        
        # Client Secret
        ttk.Label(main_frame, text="Client Secret:", font=('Helvetica', 11)).grid(
            row=2, column=0, sticky=tk.W, pady=5)
        self.client_secret_entry = ttk.Entry(main_frame, width=60, show="*")
        self.client_secret_entry.grid(row=2, column=1, pady=5, padx=(10, 0))
        
        # Show/Hide Secret
        self.show_secret_var = tk.BooleanVar()
        show_secret_check = ttk.Checkbutton(main_frame, text="Show Secret", 
                                           variable=self.show_secret_var,
                                           command=self.toggle_secret)
        show_secret_check.grid(row=3, column=1, sticky=tk.W, padx=(10, 0))
        
        # Redirect URI
        ttk.Label(main_frame, text="Redirect URI:", font=('Helvetica', 11)).grid(
            row=4, column=0, sticky=tk.W, pady=5)
        self.redirect_uri_var = tk.StringVar(value="http://127.0.0.1:8080/callback")
        redirect_uri_entry = ttk.Entry(main_frame, textvariable=self.redirect_uri_var, 
                                      width=60)
        redirect_uri_entry.grid(row=4, column=1, pady=5, padx=(10, 0))
        
        # Info label
        info_label = ttk.Label(main_frame, 
                              text="Make sure this redirect URI matches your Canva app settings exactly!",
                              font=('Helvetica', 9, 'italic'), foreground='#666666')
        info_label.grid(row=5, column=0, columnspan=2, pady=(0, 10))
        
        # PKCE Option
        self.use_pkce_var = tk.BooleanVar(value=True)
        pkce_check = ttk.Checkbutton(main_frame, text="Use PKCE (Recommended)", 
                                    variable=self.use_pkce_var)
        pkce_check.grid(row=6, column=1, sticky=tk.W, padx=(10, 0))
        
        # Scopes
        ttk.Label(main_frame, text="Scopes:", font=('Helvetica', 11)).grid(
            row=7, column=0, sticky=tk.W, pady=5)
        
        scopes_frame = ttk.Frame(main_frame)
        scopes_frame.grid(row=7, column=1, sticky=tk.W, padx=(10, 0))
        
        self.scope_vars = {
            'asset:read': tk.BooleanVar(value=True),
            'asset:write': tk.BooleanVar(value=True),
            'design:content:read': tk.BooleanVar(value=True),
            'design:content:write': tk.BooleanVar(value=True),
            'design:meta:read': tk.BooleanVar(value=True),
            'folder:read': tk.BooleanVar(value=True),
            'folder:write': tk.BooleanVar(value=True),
            'profile:read': tk.BooleanVar(value=True),
        }
        
        row_idx = 0
        col_idx = 0
        for scope, var in self.scope_vars.items():
            cb = ttk.Checkbutton(scopes_frame, text=scope, variable=var)
            cb.grid(row=row_idx, column=col_idx, sticky=tk.W, padx=(0, 15))
            col_idx += 1
            if col_idx > 2:
                col_idx = 0
                row_idx += 1
        
        # Token Expiry Display
        self.expiry_frame = ttk.Frame(main_frame)
        self.expiry_frame.grid(row=8, column=0, columnspan=2, pady=(10, 0))
        
        ttk.Label(self.expiry_frame, text="Token Expires In:", font=('Helvetica', 10, 'bold')).grid(
            row=0, column=0, padx=5)
        
        self.expiry_label = ttk.Label(self.expiry_frame, text="No active token", 
                                     font=('Helvetica', 12), foreground='#666666')
        self.expiry_label.grid(row=0, column=1, padx=5)
        
        # Authorize Button
        authorize_btn = ttk.Button(main_frame, text="1. Authorize App (Opens Browser)", 
                                   command=self.start_authorization)
        authorize_btn.grid(row=9, column=0, columnspan=2, pady=(20, 5))
        
        # Exchange Code Button
        self.exchange_btn = ttk.Button(main_frame, text="2. Exchange Code for Token", 
                                       command=self.exchange_code, state='disabled')
        self.exchange_btn.grid(row=10, column=0, columnspan=2, pady=5)
        
        # Response Section
        ttk.Label(main_frame, text="Response:", font=('Helvetica', 11, 'bold')).grid(
            row=11, column=0, columnspan=2, sticky=tk.W, pady=(20, 5))
        
        self.response_text = scrolledtext.ScrolledText(main_frame, width=85, height=12, 
                                                      wrap=tk.WORD, font=('Courier', 9))
        self.response_text.grid(row=12, column=0, columnspan=2, pady=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=13, column=0, columnspan=2, pady=10)
        
        # Copy Token Button
        self.copy_token_btn = ttk.Button(buttons_frame, text="Copy Access Token", 
                                        command=self.copy_access_token, state='disabled')
        self.copy_token_btn.grid(row=0, column=0, padx=5)
        
        # Copy Refresh Token Button
        self.copy_refresh_btn = ttk.Button(buttons_frame, text="Copy Refresh Token", 
                                          command=self.copy_refresh_token, state='disabled')
        self.copy_refresh_btn.grid(row=0, column=1, padx=5)
        
        # Refresh Token Button
        self.refresh_token_btn = ttk.Button(buttons_frame, text="Use Refresh Token", 
                                           command=self.use_refresh_token, state='disabled')
        self.refresh_token_btn.grid(row=0, column=2, padx=5)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready - Enter your Client ID and Secret, then click 'Authorize App'")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, 
                              anchor=tk.W, font=('Helvetica', 9))
        status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        self.access_token = None
        self.refresh_token = None
        self.auth_code = None
        self.state = None
        self.code_verifier = None
        self.code_challenge = None
        self.server = None
        self.server_thread = None
        self.token_expiry_time = None
        self.expiry_update_job = None
        
    def toggle_secret(self):
        if self.show_secret_var.get():
            self.client_secret_entry.config(show="")
        else:
            self.client_secret_entry.config(show="*")
    
    def get_selected_scopes(self):
        return ' '.join([scope for scope, var in self.scope_vars.items() if var.get()])
    
    def generate_pkce_pair(self):
        """Generate PKCE code_verifier and code_challenge"""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        code_verifier = code_verifier.rstrip('=')
        
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.rstrip('=')
        
        return code_verifier, code_challenge
    
    def start_expiry_countdown(self, expires_in):
        """Start countdown timer for token expiry"""
        self.token_expiry_time = datetime.now() + timedelta(seconds=expires_in)
        self.update_expiry_display()
    
    def update_expiry_display(self):
        """Update the expiry countdown display"""
        if self.expiry_update_job:
            self.root.after_cancel(self.expiry_update_job)
        
        if not self.token_expiry_time:
            self.expiry_label.config(text="No active token", foreground='#666666')
            return
        
        now = datetime.now()
        remaining = self.token_expiry_time - now
        
        if remaining.total_seconds() <= 0:
            self.expiry_label.config(text="EXPIRED", foreground='red', 
                                    font=('Helvetica', 12, 'bold'))
            self.token_expiry_time = None
            return
        
        # Calculate time remaining
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        seconds = int(remaining.total_seconds() % 60)
        
        # Color code based on time remaining
        if remaining.total_seconds() < 300:  # Less than 5 minutes
            color = 'red'
        elif remaining.total_seconds() < 900:  # Less than 15 minutes
            color = 'orange'
        else:
            color = 'green'
        
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        self.expiry_label.config(text=time_str, foreground=color, 
                                font=('Helvetica', 12, 'bold'))
        
        # Schedule next update
        self.expiry_update_job = self.root.after(1000, self.update_expiry_display)
    
    def start_authorization(self):
        client_id = self.client_id_entry.get().strip()
        
        if not client_id:
            messagebox.showerror("Error", "Please enter your Client ID")
            return
        
        self.state = secrets.token_urlsafe(32)
        
        if self.use_pkce_var.get():
            self.code_verifier, self.code_challenge = self.generate_pkce_pair()
        
        self.start_callback_server()
        
        scopes = self.get_selected_scopes()
        redirect_uri = self.redirect_uri_var.get()
        
        auth_params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'state': self.state,
            'scope': scopes
        }
        
        if self.use_pkce_var.get():
            auth_params['code_challenge'] = self.code_challenge
            auth_params['code_challenge_method'] = 's256'
        
        auth_url = f"https://www.canva.com/api/oauth/authorize?{urllib.parse.urlencode(auth_params)}"
        
        self.status_var.set("Opening browser for authorization...")
        self.response_text.delete(1.0, tk.END)
        
        info_text = f"Authorization URL:\n{auth_url}\n\n"
        if self.use_pkce_var.get():
            info_text += f"Using PKCE:\n"
            info_text += f"Code Verifier: {self.code_verifier}\n"
            info_text += f"Code Challenge: {self.code_challenge}\n\n"
        info_text += "Waiting for authorization..."
        
        self.response_text.insert(1.0, info_text)
        
        webbrowser.open(auth_url)
        
        self.status_var.set("Waiting for authorization in browser...")
    
    def start_callback_server(self):
        if self.server:
            return
        
        self.server = HTTPServer(('127.0.0.1', 8080), OAuthCallbackHandler)
        self.server.auth_code = None
        self.server.auth_error = None
        
        def run_server():
            while not self.server.auth_code and not self.server.auth_error:
                self.server.handle_request()
            
            if self.server.auth_code:
                self.auth_code = self.server.auth_code
                self.root.after(100, self.handle_auth_success)
            elif self.server.auth_error:
                self.root.after(100, lambda: self.handle_auth_error(self.server.auth_error))
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
    
    def handle_auth_success(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"AUTHORIZATION SUCCESSFUL - {timestamp}\n\n"
        message += f"Authorization Code: {self.auth_code[:20]}...\n\n"
        message += "Click 'Exchange Code for Token' to get your access token."
        
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(1.0, message)
        self.response_text.tag_add("success", "1.0", "1.end")
        self.response_text.tag_config("success", foreground="green", font=('Courier', 9, 'bold'))
        
        self.status_var.set("Authorization successful - Ready to exchange code")
        self.exchange_btn.config(state='normal')
    
    def handle_auth_error(self, error):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"✗ AUTHORIZATION FAILED - {timestamp}\n\n"
        message += f"Error: {error}"
        
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(1.0, message)
        self.response_text.tag_add("error", "1.0", "1.end")
        self.response_text.tag_config("error", foreground="red", font=('Courier', 9, 'bold'))
        
        self.status_var.set("✗ Authorization failed")
        messagebox.showerror("Authorization Failed", f"Error: {error}")
    
    def exchange_code(self):
        client_id = self.client_id_entry.get().strip()
        client_secret = self.client_secret_entry.get().strip()
        
        if not client_secret:
            messagebox.showerror("Error", "Please enter your Client Secret")
            return
        
        if not self.auth_code:
            messagebox.showerror("Error", "No authorization code available. Please authorize first.")
            return
        
        self.status_var.set("Exchanging code for token...")
        self.root.update()
        
        try:
            url = "https://api.canva.com/rest/v1/oauth/token"
            
            payload = {
                "grant_type": "authorization_code",
                "code": self.auth_code,
                "redirect_uri": self.redirect_uri_var.get(),
                "client_id": client_id,
                "client_secret": client_secret
            }
            
            if self.use_pkce_var.get() and self.code_verifier:
                payload["code_verifier"] = self.code_verifier
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = requests.post(url, data=payload, headers=headers)
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                self.refresh_token = data.get('refresh_token')
                expires_in = data.get('expires_in', 3600)
                
                # Start expiry countdown
                self.start_expiry_countdown(expires_in)
                
                formatted_response = f"✓ TOKEN EXCHANGE SUCCESSFUL - {timestamp}\n\n"
                formatted_response += f"Status Code: {response.status_code}\n\n"
                formatted_response += "Response:\n"
                formatted_response += json.dumps(data, indent=2)
                
                self.response_text.delete(1.0, tk.END)
                self.response_text.insert(1.0, formatted_response)
                self.response_text.tag_add("success", "1.0", "1.end")
                self.response_text.tag_config("success", foreground="green", font=('Courier', 9, 'bold'))
                
                self.status_var.set(f"✓ Access token generated successfully at {timestamp}")
                self.copy_token_btn.config(state='normal')
                self.copy_refresh_btn.config(state='normal')
                self.refresh_token_btn.config(state='normal')
                
                messagebox.showinfo("Success", "Access token generated successfully!")
            else:
                error_data = response.json() if response.content else {"error": "No response content"}
                
                formatted_response = f"✗ TOKEN EXCHANGE FAILED - {timestamp}\n\n"
                formatted_response += f"Status Code: {response.status_code}\n\n"
                formatted_response += "Response:\n"
                formatted_response += json.dumps(error_data, indent=2)
                
                self.response_text.delete(1.0, tk.END)
                self.response_text.insert(1.0, formatted_response)
                self.response_text.tag_add("error", "1.0", "1.end")
                self.response_text.tag_config("error", foreground="red", font=('Courier', 9, 'bold'))
                
                self.status_var.set(f"✗ Error: {response.status_code}")
                messagebox.showerror("Error", f"Failed to exchange code. Status: {response.status_code}")
                
        except Exception as e:
            error_msg = f"✗ UNEXPECTED ERROR - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n{str(e)}"
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(1.0, error_msg)
            self.status_var.set("✗ Unexpected error")
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
    
    def use_refresh_token(self):
        client_id = self.client_id_entry.get().strip()
        client_secret = self.client_secret_entry.get().strip()
        
        if not client_secret:
            messagebox.showerror("Error", "Please enter your Client Secret")
            return
        
        if not self.refresh_token:
            messagebox.showerror("Error", "No refresh token available.")
            return
        
        self.status_var.set("Using refresh token...")
        self.root.update()
        
        try:
            url = "https://api.canva.com/rest/v1/oauth/token"
            
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": client_id,
                "client_secret": client_secret
            }
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = requests.post(url, data=payload, headers=headers)
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                if 'refresh_token' in data:
                    self.refresh_token = data.get('refresh_token')
                
                expires_in = data.get('expires_in', 3600)
                
                # Restart expiry countdown
                self.start_expiry_countdown(expires_in)
                
                formatted_response = f"✓ TOKEN REFRESH SUCCESSFUL - {timestamp}\n\n"
                formatted_response += f"Status Code: {response.status_code}\n\n"
                formatted_response += "Response:\n"
                formatted_response += json.dumps(data, indent=2)
                
                self.response_text.delete(1.0, tk.END)
                self.response_text.insert(1.0, formatted_response)
                self.response_text.tag_add("success", "1.0", "1.end")
                self.response_text.tag_config("success", foreground="green", font=('Courier', 9, 'bold'))
                
                self.status_var.set(f"✓ Access token refreshed successfully at {timestamp}")
                
                messagebox.showinfo("Success", "Access token refreshed successfully!")
            else:
                error_data = response.json() if response.content else {"error": "No response content"}
                
                formatted_response = f"✗ TOKEN REFRESH FAILED - {timestamp}\n\n"
                formatted_response += f"Status Code: {response.status_code}\n\n"
                formatted_response += "Response:\n"
                formatted_response += json.dumps(error_data, indent=2)
                
                self.response_text.delete(1.0, tk.END)
                self.response_text.insert(1.0, formatted_response)
                self.response_text.tag_add("error", "1.0", "1.end")
                self.response_text.tag_config("error", foreground="red", font=('Courier', 9, 'bold'))
                
                self.status_var.set(f"✗ Error: {response.status_code}")
                messagebox.showerror("Error", f"Failed to refresh token. Status: {response.status_code}")
                
        except Exception as e:
            error_msg = f"✗ ERROR - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n{str(e)}"
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(1.0, error_msg)
            self.status_var.set("✗ Error")
            messagebox.showerror("Error", f"Error: {str(e)}")
    
    def copy_access_token(self):
        if self.access_token:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.access_token)
            self.status_var.set("✓ Access token copied to clipboard")
            messagebox.showinfo("Copied", "Access token copied to clipboard!")
    
    def copy_refresh_token(self):
        if self.refresh_token:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.refresh_token)
            self.status_var.set("✓ Refresh token copied to clipboard")
            messagebox.showinfo("Copied", "Refresh token copied to clipboard!")

if __name__ == "__main__":
    root = tk.Tk()
    app = CanvaOAuthApp(root)
    root.mainloop()