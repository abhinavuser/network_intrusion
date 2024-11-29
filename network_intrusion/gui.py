import tkinter as tk
import subprocess
import os

def list_scripts():
    scripts = [f for f in os.listdir('.') if f.endswith('.py')]
    return scripts

def run_script(script_name):
    subprocess.run(['python', script_name], shell=True)

def create_buttons(root, scripts):
    for script in scripts:
        button = tk.Button(
            root,
            text=script,
            command=lambda s=script: run_script(s),
            font=("Arial", 12),
            fg="white",
            bg="#4CAF50",
            activebackground="#45a049", 
            relief="raised",
            padx=20,
            pady=10,
            bd=3
        )
        button.pack(pady=10, padx=30, fill='x')  

def create_header(root):
    header = tk.Label(
        root,
        text="Network Intrusion Detection",
        font=("Helvetica", 16, 'bold'),
        bg="#333333",
        fg="white",
        pady=10
    )
    header.pack(fill='x')

def main():
    root = tk.Tk()
    root.title("Python Script Interface")
    root.geometry("400x500")  
    root.config(bg="#f4f4f4")  
    create_header(root)
    scripts = list_scripts()
    create_buttons(root, scripts)
    window_width = 400
    window_height = 500
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    position_top = int(screen_height / 2 - window_height / 2)
    position_right = int(screen_width / 2 - window_width / 2)
    root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')
    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=3)

    root.mainloop()

if __name__ == "__main__":
    main()
