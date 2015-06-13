from time import time
R.<x> = ZZ['x'];

class NTRUEncrypt(object):

	def sample(self,NN, o,mo):
	    s=[1]*o+[-1]*mo+[0]*(NN-o-mo)
	    shuffle(s)
	    return R(s)

	def __pn__(self,d1,d2,d3):
		a=ZZ.random_element(2*d1, self.n-d2)
		p1=self.sample(a, d1, d1)
		p2=self.sample(self.n-a, d2, d2)
		p3=self.sample(self.n, d3, d3)
		poly=p1*p2+p3
		return poly

	#reduces the coefficients of polynomial f modulo pp
	#and "fixes" them so that they belong to [-pp/2,pp/2]
	def modCoeffs(self,f,pp):
	    clist=f.list()
	    p2=pp/2
	    for i in range(len(clist)):
	        clist[i] = clist[i]%pp
	        if clist[i]>p2:
	            clist[i]-=pp
	    return R(clist)

	def encrypt(self,h,m):
		s=self.sample(self.n, self.Dm, self.Dm-1)
		c=s*h+m
		c=c%(x^self.n-1)
		c=self.modCoeffs(c,self.q)
		return c

	def decrypt(self,c,Priv):
		f,fp=Priv
		a=f*c
		a=a%(x^self.n-1)
		a=self.modCoeffs(a,self.q)
		a=a*fp
		a=a%(x^self.n-1)
		a=self.modCoeffs(a,self.p)
		return a

	def __inv_poly_mod2__(self,poly):
		k=0;b=1;c=0*x;
		f=poly;g=x^self.n-1
		f=self.modCoeffs(f, 2)
		res=False
		while True:
			while f(0)==0 and not f.is_zero():
				f=f.shift(-1)
				c=c.shift(1)
				c=self.modCoeffs(c, 2)
				k+=1
			if f.is_one():
				e=(-k)%self.n
				retval= x^e*b 
				res=True
				break
			elif f.degree()==-1 or f.is_zero():
				break
			if f.degree()<g.degree():
				f,g=g,f
				b,c=c,b
			f=f+g
			b=b+c
			f=self.modCoeffs(f, 2)
			c=self.modCoeffs(c, 2)
		if res:
			retval=retval%(x^self.n-1)
			retval=self.modCoeffs(retval, 2)
			return True, retval
		else:
			return False,0

	def __inv_poly_mod3__(self,poly):
		k=0;b=1;c=0*x;
		f=poly;g=x^self.n-1
		res=False
		while True:
			while f(0)==0 and not f.is_zero():
				f=f.shift(-1)
				c=c.shift(1)
				k+=1
			if f.is_one():
				e=(-k)%self.n
				retval= x^e*b 
				res=True
				break
			elif (-f).is_one():
				e=(-k)%self.n
				retval= -x^e*b 
				res=True
				break
			elif f.degree()==-1 or f.is_zero():
				break
			if f.degree()<g.degree():
				f,g=g,f
				b,c=c,b
			if f(0)==g(0):
				f=f-g
				b=b-c
			else:
				f=f+g
				b=b+c
			f=self.modCoeffs(f, 3)
			c=self.modCoeffs(c, 3)
		if res:
			retval=retval%(x^self.n-1)
			retval=self.modCoeffs(retval, 3)
			return True, retval
		else:
			return False,0

	def __inv_poly_mod_prime_pow__(self,poly):
		res,b=self.__inv_poly_mod2__(poly)
		if res:
			qr=2
			while qr<self.q:
				qr=qr^2
				b=b*(2-poly*b)
				b=b%(x^self.n-1)
				b=self.modCoeffs(b, self.q)
			return True,b
		else:
			return False,0

	def __gen_priv_key__(self):
		res=False
		while (res==False):
			poly=self.__pn__(self.D1,self.D2,self.D3)
			poly=1+2*poly
			ppInv=self.__inv_poly_mod3__(poly)[1]
			res,pqInv=self.__inv_poly_mod_prime_pow__(poly)
		return poly,ppInv,pqInv

	def gen_keys(self):
		f,fp,fq=self.__gen_priv_key__()
		g=self.sample(n,self.Dg,self.Dg-1)
		h=self.p*g*fq
		h=h%(x^self.n-1)
		h=self.modCoeffs(h,self.q)
		return h,(f,fp)

	def __init__(self, SECLEVEL):
		self.p=3
		self.q=2048
		if SECLEVEL==128:
			self.n=439
			self.D1=9;self.D2=8;self.D3=5
			self.Dg=146;self.Dm=112
		elif SECLEVEL==192:
			self.n=593
			self.D1=10;self.D2=10;self.D3=8
			self.Dg=197;self.Dm=158
		else:
			self.n=743
			self.D1=11;self.D2=11;self.D3=15
			self.Dg=247;self.Dm=204

ntru=NTRUEncrypt(128)
n=ntru.n; dm=ntru.Dm
m=ntru.sample(n,dm,dm-1)
ts=time()
h,Priv=ntru.gen_keys()
kgtime= time()-ts
ts=time()
cc=ntru.encrypt(h,m)
enctime=time()-ts
ts=time()
mm=ntru.decrypt(cc,Priv)
dectime=time()-ts
print kgtime,enctime,dectime
print mm==m

m1=ntru.sample(n,dm,dm-1)
m2=ntru.sample(n,dm,dm-1)
cc1=ntru.encrypt(h,m1)
cc2=ntru.encrypt(h,m2)

mm=ntru.decrypt(cc1+cc2,Priv)
mmm=ntru.modCoeffs(m1+m2,ntru.p)
print mm==mmm