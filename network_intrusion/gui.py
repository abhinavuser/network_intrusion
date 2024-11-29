import tkinter as tk
import subprocess
import os

def list_scripts():
    scripts = [f for f in os.listdir('.') if f.endswith('.py')]
    return scripts


def run_script(script_name):
    subprocess.run(['python', script_name])


def create_buttons(root, scripts):
    for script in scripts:
        button = tk.Button(root, text=script, command=lambda s=script: run_script(s))
        button.pack(pady=5)

def main():
    root = tk.Tk()
    root.title("Interface")
    root.geometry("300x400")  

    scripts = list_scripts()
    create_buttons(root, scripts)

    root.mainloop()

if __name__ == "__main__":
    main()
