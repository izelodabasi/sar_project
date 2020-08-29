import random

#generate random rules
def get_rules(self, number):
    self.rule_table = {}

    self.logger.info("--- Rules ---\n") 

    #determine rules
    for i in range(number):
        rule = "R" + str(i)
        fields = []
        for j in range(5):
            #ip fields
            if(j <= 1):
                len = random.randint(0,4)
                f = "" 
                for i in range(len): 
                    temp = str(random.randint(0, 1)) 
                    f += temp
                f+= "*"
            #proto field
            elif(j == 2):
                f = random.choice(["*", "1", "6"])
            #port fields
            else:
                f = str(random.randint(0,1))
            fields.append(f)

        fields.append("allow")
        self.rule_table[rule] = fields
    
    self.logger.info("%s\n" % self.rule_table)
    return self.rule_table
    
    
#create cross-producting table
def table_cross_producting(self, rule_table):
	self.logger.info("--- cross-producting table ---\n") 
	CP = []
	
	for i in range(5):

		#for destination ip and source ip fields
		if(i == 0 or i == 1):
			f = []
			
			#calculate ranges
			for j in self.rule_table:
				f.append(self.rule_table[j][i])
			f.sort(key=len)
			f_len = len(max(f, key=len))
			R = []
			for j in range(len(f)):
				s = f[j][0:-1]
				s1 = s + (f_len-len(s)) * "0"
				s2 = s + (f_len-len(s)) * "1"
				if (j == 0):
					R.append([s1,s2])

				while (s1 in [value[0] for value in R] and s2 not in [value[1] for value in R]):
					ind = ([value[0] for value in R].index(s1))
					end =  ([value[1] for value in R][ind])  
					start = bin(int(s2, 2) + int('1',2)).replace('0b','')
					start = (f_len-len(start)) * "0"+ start
					R.pop(ind)
					R.append([s1,s2])
					R.append([start,end])

				while (s1 not in [value[0] for value in R] and s2 in [value[1] for value in R]):
					ind = ([value[1] for value in R].index(s2))
					start =  ([value[0] for value in R][ind])  
					end = bin(int(s1, 2) - int('1',2)).replace('0b','')
					end = (f_len-len(end)) * "0"+ end
					R.pop(ind)
					R.append([s1,s2])
					R.append([start,end])

				while (s1 not in [value[0] for value in R] and s2 not in [value[1] for value in R]):
					R.append([s1,s2])

			#assign rules to right ranges
			T = {}
			for key, value in sorted(self.rule_table.items()):
				v = value[i][0:-1]
				x = len(v)
				for j in range(len(R)):
					if(R[j][0][0:x] <= v and v <= R[j][1][0:x]):
						new_key = R[j][0] + "-" + R[j][1]
						if new_key in T:
							T[new_key].append(key)
						else:
							T[new_key] = [key]
			
			self.logger.info("T %s: %s\n" % (i,T))
			CP.append(T)

		#for other fields
		else:
			T = {}
			for key, value in sorted(self.rule_table.items()):
				v = value[i]
				if v in T:
					T[v].append(key)
				else:
					T[v] = [key]
		
			self.logger.info("T %s: %s\n" % (i,T))
			CP.append(T)
	
	#self.logger.info("Cross-producting: %s \n" % (CP))
	return CP


#find matching rule and action according to cross-producting 
def cross_producting_classification(self, cp, src_ip, dst_ip, proto, sport, dport):
	action = "deny"
	self.logger.info("--- cross-producting classification ---") 

	match_rules = []

	for i in range(5):
		temp = []	

		#find matching rules for ip fields
		if(i <= 1):
			if(i == 0 ):
				ip = src_ip
			else:
				ip = dst_ip
			pre = ''.join([ bin(int(x))[2:].rjust(8,'0') for x in ip.split('.')])
			for key, values in cp[i].items():
				m = key.index('-')
				start = key[:m]
				end = key[(m+1):]
				bin_len = len(start)
				bin_pre = pre[0:bin_len]
				if(start <= bin_pre and bin_pre <= end):
					for value in values:
						temp.append(value)	
		
		#find matching rules for other fields
		else:
			if(i == 2):
				value = proto
			elif(i == 3):
				value = sport
			else:
				value = dport
			for key, values in cp[i].items():
				if(key == value or key =="*"):	
					for value in values:
						temp.append(value)
		
		#compare matching rules for each fields
		if(i == 0):
			match_rules = temp
		else:
			match_rules = [x for x in match_rules if x in temp]

	#find highest priority rule
	if(len(match_rules) != 0):	
		match_rules.sort()
		self.logger.info(" Matched rules : %s" % (match_rules))
		rule = match_rules[0]
		match = self.rule_table[rule]
		action = match[5]
		#self.counters[rule] = self.counters[rule] + 1
		self.logger.info(" --- Packet matched rule %s. Action is %s" % (rule, match[5]))
	return action



#create bit-map table
def table_bit_map(self, rule_table):
	self.logger.info("--- bit_map table ---\n") 
	BM = []
	
	for i in range(5):

		#for destination ip and source ip fields
		if(i == 0 or i == 1):
			f = []
			
			#calculate intervals
			for j in self.rule_table:
				f.append(self.rule_table[j][i])
			f.sort(key=len)
			f_len = len(max(f, key=len))
			R = []
			for j in range(len(f)):
				s = f[j][0:-1]
				s1 = s + (f_len-len(s)) * "0"
				s2 = s + (f_len-len(s)) * "1"
				if (j == 0):
					R.append([s1,s2])

				while (s1 in [value[0] for value in R] and s2 not in [value[1] for value in R]):
					ind = ([value[0] for value in R].index(s1))
					end =  ([value[1] for value in R][ind])  
					start = bin(int(s2, 2) + int('1',2)).replace('0b','')
					start = (f_len-len(start)) * "0"+ start
					R.pop(ind)
					R.append([s1,s2])
					R.append([start,end])

				while (s1 not in [value[0] for value in R] and s2 in [value[1] for value in R]):
					ind = ([value[1] for value in R].index(s2))
					start =  ([value[0] for value in R][ind])  
					end = bin(int(s1, 2) - int('1',2)).replace('0b','')
					end = (f_len-len(end)) * "0"+ end
					R.pop(ind)
					R.append([s1,s2])
					R.append([start,end])

				while (s1 not in [value[0] for value in R] and s2 not in [value[1] for value in R]):
					R.append([s1,s2])

			#calculate bitmap
			T = {}
			for key, value in sorted(self.rule_table.items()):
				v = value[i][0:-1]
				x = len(v)
				for j in range(len(R)):
					new_key = R[j][0] + "-" + R[j][1]
					if(R[j][0][0:x] <= v and v <= R[j][1][0:x]):
						if new_key in T:
							T[new_key].append(1)
						else:
							T[new_key] = [1]
					else:
						if new_key in T:
							T[new_key].append(0)
						else:
							T[new_key] = [0]
			
			self.logger.info("T %s: %s\n" % (i,T))
			BM.append(T)

		#for other fields
		else:
			T = {}
			x = []
			f =[]
			for j in self.rule_table:
				if self.rule_table[j][i] not in f:
					f.append(self.rule_table[j][i])
			f_len = len(f)

			#calculate intervals and their bitmaps
			for key, value in sorted(self.rule_table.items()):
				v = value[i]
				for k in range (f_len):
					if(f[k] == v):
						if f[k] in T:
							T[f[k]].append(1)
						else:
							T[f[k]] = [1]
					else:
						if f[k] in T:
							T[f[k]].append(0)
						else:
							T[f[k]] = [0]
			
			self.logger.info("T %s: %s\n" % (i,T))
			BM.append(T)
	#self.logger.info("Bit-map: %s \n" % (BM))
	return BM



#find matching rule and action according to bit-map 
def bit_map_classification(self, bm, src_ip, dst_ip, proto, sport, dport):
	action = "deny"
	self.logger.info("--- bit-map classification ---") 

	for i in range(5):

		#find matching rules for ip fields
		if(i <= 1):
			temp = []		
			if(i == 0 ):
				ip = src_ip
			else:
				ip = dst_ip
			pre = ''.join([ bin(int(x))[2:].rjust(8,'0') for x in ip.split('.')])
			for key, values in bm[i].items():
				m = key.index('-')
				start = key[:m]
				end = key[(m+1):]
				bin_len = len(key)
				bin_pre = pre[0:bin_len]
				if(start <= bin_pre and bin_pre <= end):
					temp = values

		#find matching rules for other fields
		else:
			if(i == 2):
				value = proto
			elif(i == 3):
				value = sport
			else:
				value = dport
			temp = [0]*len(self.rule_table)
			for key, values in bm[i].items():
				if(key == value or key == "*"):	
					temp = [(a or b) for a, b in zip(temp, values)]
		
		#compare matching rules for each fields
		if(i == 0):
			match_rules = temp
		else:
			match_rules = [a * b for a, b in zip(temp, match_rules)]

	#find highest priority rule
	if 1 in match_rules:
		rule = match_rules.index(1)
		rule = sorted(self.rule_table.keys())[rule]
		match = self.rule_table[rule]
		action = match[5]
		#self.counters[rule] = self.counters[rule] + 1
		self.logger.info(" --- Packet matched rule %s. Action is %s" % (rule, match[5]))
	
	return action