'use client';

import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer 
} from 'recharts';

const data = [
  { time: '00:00', score: 85 },
  { time: '04:00', score: 88 },
  { time: '08:00', score: 92 },
  { time: '12:00', score: 90 },
  { time: '16:00', score: 95 },
  { time: '20:00', score: 97 },
  { time: '24:00', score: 99 },
];

export default function PostureTrendChart() {
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis dataKey="time" stroke="#9CA3AF" fontSize={12} tickLine={false} axisLine={false} />
          <YAxis stroke="#9CA3AF" fontSize={12} tickLine={false} axisLine={false} domain={[0, 100]} />
          <Tooltip 
            contentStyle={{ backgroundColor: '#1F2937', border: 'none', borderRadius: '8px', color: '#F3F4F6' }}
            itemStyle={{ color: '#818CF8' }}
          />
          <Line type="monotone" dataKey="score" stroke="#6366F1" strokeWidth={3} dot={{ r: 4, fill: '#4F46E5', strokeWidth: 0 }} activeDot={{ r: 6, fill: '#818CF8' }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
