import Tkinter as tk
import tkSimpleDialog as msg
import HD_Wallet_Details
import Addresses_Details
import ttk

#Rough Protype

key1 = 'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73'
font_title = ('Emilbus', 15, 'underline')

def run_derived_key(controller):
	controller.show_frame(Derived_key)
	controller.frames[Derived_key].run_program(controller)

def run_address_details(controller,wallet, master_wallet = False):
	controller.show_frame(Key_Details)
	controller.frames[Key_Details].run_program(controller,wallet,master_wallet)

class BIP32_details(tk.Tk):
	#Root class
	def __init__(self,*args,**kwargs):
		tk.Tk.__init__(self,*args,**kwargs)
		self.geometry('1325x500')
		
		try:
			tk.Tk.wm_title(self, "BIP32 Extended Key Details")
		except:
			pass

		container = tk.Frame()
		container.pack()
		container.grid_rowconfigure(0, weight = 1)
		container.grid_columnconfigure(0, weight = 1)

		self.frames = {} #Container for all frames

		for F in (Master_key,Key_Details,Derived_key):
			frame = F(container,self)#Where it gets the functions from
			self.frames[F] = frame
			frame.grid(row = 0, column = 0, sticky = 'nsew')

		self.show_frame(Master_key)


	def show_frame(self,page):
		frame = self.frames[page]
		frame.tkraise()

class Master_key(tk.Frame):
	def __init__(self,parent,controller):
		tk.Frame.__init__(self,parent)

		title = tk.Label(self,text = "Master Key Details", font = font_title)
		title.grid(row = 0, column = 0)
		
		wallet = HD_Wallet_Details.HD_wallet_details(key1)
		long_text = wallet.dump_string()
		
		info1 = tk.Text(self,width = 165,height = 15)
		info1.insert(tk.INSERT,long_text)
		info1.config(state = tk.DISABLED)
		info1.grid(row = 2,column = 0)

		button1 = ttk.Button(self,text = "Derive Key",command = lambda: run_derived_key(controller))
		button1.grid(row = 3,column = 0, sticky = 'e',padx = 450)

		button2 = ttk.Button(self,text = "Master Key Details",command = lambda: run_address_details(controller,wallet,True))
		button2.grid(row = 3,column = 0,sticky = 'w',padx = 450)

class Key_Details(tk.Frame):
	def __init__(self,parent,controller):
		tk.Frame.__init__(self,parent)
	
	def run_program(self,controller,wallet, master_wallet):	
		title = tk.Label (self, text = "Key Details", font = font_title)
		title.grid(row = 0, column = 0)
		
		if wallet.private:
			address = Addresses_Details.Private_key(wallet.key)
		else:
			address = Addresses_Details.Public_key(wallet.key)

		Key_details_text =  address.dump_string()

		info1 = tk.Text(self,width = 165,height = 15)
		info1.insert(tk.INSERT,Key_details_text)
		info1.config(state = tk.DISABLED)
		info1.grid(row = 2,column = 0)

		button1 = ttk.Button(self,text = 'Return Home', command = lambda: controller.show_frame(Master_key))
		button1.grid(row = 3,sticky = 'w',padx = 450)
		if not master_wallet:
			button1 = ttk.Button(self,text = 'Return To Derived Key', command = lambda: controller.show_frame(Derived_key))
			button1.grid(row = 3,sticky = 'e',padx = 450)

class Derived_key(tk.Frame):
	def __init__(self,parent,controller):
		tk.Frame.__init__(self,parent)
		

	def run_program(self,controller):
		number = msg.askinteger("Derived Number", "Enter Derived Number")
		title = tk.Label (self, text = "Derived Key", font = font_title)
		title.grid(row = 0, column = 0)

		nkey = tk.Label (self, text = number)
		nkey.grid(row = 1, column = 0)

		wallet = HD_Wallet_Details.HD_wallet_details(key1)
		(key,chain,depth,fingerprint,Child_number,Private) = wallet.CKDpriv(number)
		derived = HD_Wallet_Details.HD_wallet_details(HD_Wallet_Details.serialize_Wallet(key,chain,depth,fingerprint,Child_number,Private))
		
		string = derived.dump_string()

		info1 = tk.Text(self,width = 165,height = 15)
		info1.insert(tk.INSERT,string)
		info1.config(state = tk.DISABLED)
		info1.grid(row = 2,column = 0)

		button1 = ttk.Button(self,text = 'Return Home', command = lambda: controller.show_frame(Master_key))
		button1.grid(row = 3,sticky = 'e',padx = 450)

		button2 = ttk.Button(self,text = 'Address Details', command = lambda: run_address_details(controller,derived))
		button2.grid(row = 3,sticky = 'w',padx = 450)

app =  BIP32_details()
app.mainloop()