class file:
    def rea(self):
    	from sys import argv
    	self.script,self.fil=argv
    	fd=open(self.fil)
    	self.txt=fd.read()
class exe15(file):
    def method(self):
	file.rea(self)
	print 'file name: ',self.fil
	print self.txt

a=exe15()
a.method()
    
