'use client';

import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend
} from 'recharts';

const data = [
  { name: 'Misconfigurations', value: 45 },
  { name: 'Malware', value: 15 },
  { name: 'Outdated Software', value: 25 },
  { name: 'Unauthorized Access', value: 15 },
];

const COLORS = ['#F59E0B', '#EF4444', '#3B82F6', '#10B981'];

export default function ThreatDistributionChart() {
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={5}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip 
            contentStyle={{ backgroundColor: '#1F2937', border: 'none', borderRadius: '8px', color: '#F3F4F6' }}
            itemStyle={{ color: '#fff' }}
          />
          <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: '12px', color: '#9CA3AF' }}/>
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
